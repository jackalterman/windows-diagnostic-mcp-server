#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Comprehensive Windows Event Log Analyzer and Search Tool
.DESCRIPTION
    Searches, filters, and analyzes Windows Event Logs across Security, Application, System, and custom logs
    Provides security analysis, error correlation, and anomaly detection
.NOTES
    Requires Administrator privileges for Security log access
    Performance may vary based on log size and search criteria
.EXAMPLE
    .\EventLog-Analyzer.ps1 -LogNames "Security","System" -Hours 24 -ErrorsOnly
.EXAMPLE
    .\EventLog-Analyzer.ps1 -SearchTerms "logon","authentication" -Detailed -ExportJson
#>

param(
    [string[]]$LogNames = @("Security", "System", "Application"),
    [string[]]$SearchTerms = @(),
    [int[]]$EventIDs = @(),
    [string[]]$Sources = @(),
    [int]$Hours = 24,
    [int]$Days = 0,
    [string]$StartTime = "",
    [string]$EndTime = "",
    [switch]$ErrorsOnly,
    [switch]$WarningsOnly,
    [switch]$CriticalOnly,
    [switch]$SecurityAnalysis,
    [switch]$Detailed,
    [switch]$ExportJson,
    [switch]$ExportCsv,
    [string]$OutputPath = ".\eventlog-analysis",
    [int]$MaxEvents = 1000,
    [switch]$ShowStats,
    [switch]$GroupBySource,
    [switch]$TimelineView
)

# Initialize results object
$Results = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ComputerName = $env:COMPUTERNAME
    AnalysisPeriod = @{}
    LogSummary = @{}
    Events = @()
    SecurityAnalysis = @{}
    ErrorPatterns = @{}
    Statistics = @{}
    Recommendations = @()
    Errors = @()
}

Write-Host "📋 Windows Event Log Analyzer - $($Results.Timestamp)" -ForegroundColor Cyan
Write-Host "=" * 70

#region Time Range Calculation
if ($Days -gt 0) { $Hours = $Days * 24 }

if ($StartTime -and $EndTime) {
    try {
        $startDateTime = [DateTime]::Parse($StartTime)
        $endDateTime = [DateTime]::Parse($EndTime)
    } catch {
        Write-Host "❌ Invalid date format. Using default time range." -ForegroundColor Red
        $startDateTime = (Get-Date).AddHours(-$Hours)
        $endDateTime = Get-Date
    }
} else {
    $startDateTime = (Get-Date).AddHours(-$Hours)
    $endDateTime = Get-Date
}

$Results.AnalysisPeriod = @{
    StartTime = $startDateTime.ToString("yyyy-MM-dd HH:mm:ss")
    EndTime = $endDateTime.ToString("yyyy-MM-dd HH:mm:ss")
    Duration = "$Hours hours"
}

Write-Host "🕐 Analysis Period: $($startDateTime.ToString('yyyy-MM-dd HH:mm')) to $($endDateTime.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Yellow
#endregion

#region Log Availability Check
Write-Host "`n📚 Available Event Logs" -ForegroundColor Yellow

# Suppress non-critical warnings about logs requiring elevated privileges
$availableLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | 
                 Where-Object { $_.RecordCount -gt 0 } | 
                 Sort-Object LogName
$logStats = @{}

foreach ($logName in $LogNames) {
    $logInfo = $availableLogs | Where-Object { $_.LogName -eq $logName }
    if ($logInfo) {
        $logStats[$logName] = @{
            RecordCount = $logInfo.RecordCount
            FileSize = [math]::Round($logInfo.FileSize / 1MB, 2)
            LastWriteTime = $logInfo.LastWriteTime
            IsEnabled = $logInfo.IsEnabled
            Available = $true
        }
        Write-Host "  🟢 ${logName}: $($logInfo.RecordCount) records ($($logStats[$logName].FileSize) MB)" -ForegroundColor Green
    } else {
        $logStats[$logName] = @{ Available = $false }
        Write-Host "  🔴 ${logName}: Not available or empty" -ForegroundColor Red
    }
}

$Results.LogSummary = $logStats
#endregion

#region Event Search and Collection
Write-Host "`n🔍 Searching Event Logs..." -ForegroundColor Yellow

$allEvents = @()
$totalEventsFound = 0

foreach ($logName in $LogNames) {
    if (-not $logStats[$logName].Available) { continue }
    
    try {
        Write-Host "  📖 Processing ${logName} log..." -ForegroundColor Cyan
        
        # Build filter hashtable
        $filterHashtable = @{
            LogName = $logName
            StartTime = $startDateTime
            EndTime = $endDateTime
        }
        
        # Add level filters
        if ($ErrorsOnly) { $filterHashtable.Level = 2 }
        elseif ($WarningsOnly) { $filterHashtable.Level = 3 }
        elseif ($CriticalOnly) { $filterHashtable.Level = 1 }
        
        # Add event ID filter
        if ($EventIDs.Count -gt 0) { $filterHashtable.ID = $EventIDs }
        
        # Get events with filter
        $events = Get-WinEvent -FilterHashtable $filterHashtable -MaxEvents $MaxEvents -ErrorAction Stop
        
        # Additional filtering
        if ($SearchTerms.Count -gt 0) {
            $events = $events | Where-Object {
                $message = $_.Message
                $found = $false
                foreach ($term in $SearchTerms) {
                    if ($message -like "*$term*") { $found = $true; break }
                }
                $found
            }
        }
        
        if ($Sources.Count -gt 0) {
            $events = $events | Where-Object { $_.ProviderName -in $Sources }
        }
        
        $logEventCount = $events.Count
        $totalEventsFound += $logEventCount
        
        Write-Host "    Found: $logEventCount events" -ForegroundColor Green
        
        # Process events
        foreach ($event in $events) {
            $eventObj = @{
                TimeCreated = $event.TimeCreated
                LogName = $event.LogName
                Level = $event.Level
                LevelDisplayName = $event.LevelDisplayName
                Id = $event.Id
                ProviderName = $event.ProviderName
                TaskDisplayName = $event.TaskDisplayName
                Message = $event.Message
                UserId = $event.UserId
                ProcessId = $event.ProcessId
                ThreadId = $event.ThreadId
                MachineName = $event.MachineName
                RecordId = $event.RecordId
            }
            
            $allEvents += $eventObj
        }
        
    } catch {
        Write-Host "    ❌ Error accessing ${logName}: $($_.Exception.Message)" -ForegroundColor Red
        $Results.Errors += "Error accessing ${logName}: $($_.Exception.Message)"
    }
}

$Results.Events = $allEvents | Sort-Object TimeCreated -Descending
Write-Host "`n📊 Total Events Found: $totalEventsFound" -ForegroundColor Green
#endregion

#region Security Analysis
if ($SecurityAnalysis -or "Security" -in $LogNames) {
    Write-Host "`n🛡️  Security Event Analysis" -ForegroundColor Yellow
    
    $securityEvents = $Results.Events | Where-Object { $_.LogName -eq "Security" }
    
    if ($securityEvents) {
        $secAnalysis = @{
            LogonEvents = @()
            FailedLogons = @()
            AccountLockouts = @()
            PrivilegeUse = @()
            PolicyChanges = @()
            SuspiciousActivity = @()
        }
        
        # Logon Analysis (Event IDs: 4624, 4625, 4634, 4647, 4648)
        $logonSuccess = $securityEvents | Where-Object { $_.Id -eq 4624 }
        $logonFailure = $securityEvents | Where-Object { $_.Id -eq 4625 }
        $logoff = $securityEvents | Where-Object { $_.Id -in @(4634, 4647) }
        $explicitLogon = $securityEvents | Where-Object { $_.Id -eq 4648 }
        
        Write-Host "  🔐 Logon Activity:"
        Write-Host "    Successful Logons: $($logonSuccess.Count)"
        Write-Host "    Failed Logons: $($logonFailure.Count)"
        Write-Host "    Logoffs: $($logoff.Count)"
        Write-Host "    Explicit Credential Use: $($explicitLogon.Count)"
        
        # Account Lockouts (Event ID: 4740)
        $accountLockouts = $securityEvents | Where-Object { $_.Id -eq 4740 }
        if ($accountLockouts) {
            Write-Host "    ⚠️  Account Lockouts: $($accountLockouts.Count)" -ForegroundColor Yellow
            $secAnalysis.AccountLockouts = $accountLockouts
        }
        
        # Failed logon patterns
        if ($logonFailure.Count -gt 0) {
            $failedLogonsByUser = $logonFailure | Group-Object { 
                if ($_.Message -match "Account Name:\s+(.+)") { $matches[1].Trim() } else { "Unknown" }
            } | Sort-Object Count -Descending | Select-Object -First 5
            
            Write-Host "  🚨 Top Failed Logon Accounts:"
            foreach ($group in $failedLogonsByUser) {
                Write-Host "    $($group.Name): $($group.Count) attempts"
                if ($group.Count -gt 10) {
                    Write-Host "      ⚠️  Potential brute force attack!" -ForegroundColor Red
                    $secAnalysis.SuspiciousActivity += "High failed logon attempts for user: $($group.Name)"
                }
            }
        }
        
        # Privilege Use (Event IDs: 4672, 4673, 4674)
        $privilegeUse = $securityEvents | Where-Object { $_.Id -in @(4672, 4673, 4674) }
        if ($privilegeUse) {
            Write-Host "  👑 Privilege Use Events: $($privilegeUse.Count)"
            $secAnalysis.PrivilegeUse = $privilegeUse
        }
        
        # Policy Changes (Event IDs: 4719, 4902, 4904, 4905, 4906, 4907, 4912)
        $policyChanges = $securityEvents | Where-Object { $_.Id -in @(4719, 4902, 4904, 4905, 4906, 4907, 4912) }
        if ($policyChanges) {
            Write-Host "  📝 Policy Changes: $($policyChanges.Count)"
            $secAnalysis.PolicyChanges = $policyChanges
        }
        
        # Process and Object Access
        $processCreation = $securityEvents | Where-Object { $_.Id -eq 4688 }
        $objectAccess = $securityEvents | Where-Object { $_.Id -in @(4656, 4658, 4663) }
        
        if ($processCreation.Count -gt 0) {
            Write-Host "  🏃 Process Creation Events: $($processCreation.Count)"
        }
        if ($objectAccess.Count -gt 0) {
            Write-Host "  📁 Object Access Events: $($objectAccess.Count)"
        }
        
        $Results.SecurityAnalysis = $secAnalysis
    } else {
        Write-Host "  ⚠️  No Security events found in the specified time range" -ForegroundColor Yellow
    }
}
#endregion

#region Error Pattern Analysis
Write-Host "`n🔍 Error Pattern Analysis" -ForegroundColor Yellow

$errorEvents = $Results.Events | Where-Object { $_.Level -in @(1, 2) } # Critical and Error levels
$warningEvents = $Results.Events | Where-Object { $_.Level -eq 3 } # Warning level

if ($errorEvents.Count -gt 0) {
    # Group by Event ID
    $errorsByEventId = $errorEvents | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10
    
    Write-Host "  🔴 Top Error Event IDs:"
    foreach ($group in $errorsByEventId) {
        $sampleEvent = $group.Group[0]
        Write-Host "    Event $($group.Name): $($group.Count) occurrences"
        Write-Host "      Source: $($sampleEvent.ProviderName)"
        Write-Host "      Level: $($sampleEvent.LevelDisplayName)"
        if ($Detailed) {
            $shortMessage = if ($sampleEvent.Message.Length -gt 100) { 
                $sampleEvent.Message.Substring(0, 100) + "..." 
            } else { 
                $sampleEvent.Message 
            }
            Write-Host "      Sample: $shortMessage" -ForegroundColor Gray
        }
        Write-Host ""
    }
    
    # Group by Source
    $errorsBySource = $errorEvents | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 10
    
    Write-Host "  📋 Top Error Sources:"
    foreach ($group in $errorsBySource) {
        Write-Host "    $($group.Name): $($group.Count) errors"
    }
    
    # Time-based analysis
    $recentErrors = $errorEvents | Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-1) }
    if ($recentErrors.Count -gt 0) {
        Write-Host "`n  ⏰ Recent Errors (Last Hour): $($recentErrors.Count)" -ForegroundColor Red
        
        if ($recentErrors.Count -gt 20) {
            Write-Host "    ⚠️  High error rate detected!" -ForegroundColor Red
            $Results.Recommendations += "Investigate high error rate - $($recentErrors.Count) errors in the last hour"
        }
    }
    
    $Results.ErrorPatterns = @{
        TotalErrors = $errorEvents.Count
        TotalWarnings = $warningEvents.Count
        TopErrorEventIds = $errorsByEventId
        TopErrorSources = $errorsBySource
        RecentErrorCount = $recentErrors.Count
    }
} else {
    Write-Host "  🟢 No error events found in the specified time range" -ForegroundColor Green
}
#endregion

#region System Events Analysis
Write-Host "`n🖥️  System Events Analysis" -ForegroundColor Yellow

$systemEvents = $Results.Events | Where-Object { $_.LogName -eq "System" }

if ($systemEvents.Count -gt 0) {
    # Boot/Shutdown events
    $bootEvents = $systemEvents | Where-Object { $_.Id -in @(6005, 6006, 6009, 6013) }
    $shutdownEvents = $systemEvents | Where-Object { $_.Id -in @(1074, 6006, 6008) }
    $unexpectedShutdowns = $systemEvents | Where-Object { $_.Id -eq 6008 }
    
    Write-Host "  🔄 Boot/Shutdown Activity:"
    Write-Host "    Boot Events: $($bootEvents.Count)"
    Write-Host "    Shutdown Events: $($shutdownEvents.Count)"
    if ($unexpectedShutdowns.Count -gt 0) {
        Write-Host "    ⚠️  Unexpected Shutdowns: $($unexpectedShutdowns.Count)" -ForegroundColor Yellow
        $Results.Recommendations += "Investigate unexpected shutdowns - possible hardware or power issues"
    }
    
    # Service events
    $serviceStart = $systemEvents | Where-Object { $_.Id -eq 7036 -and $_.Message -like "*running*" }
    $serviceStop = $systemEvents | Where-Object { $_.Id -eq 7036 -and $_.Message -like "*stopped*" }
    $serviceFailed = $systemEvents | Where-Object { $_.Id -in @(7022, 7023, 7024, 7026, 7031, 7032, 7034) }
    
    Write-Host "  🔧 Service Activity:"
    Write-Host "    Services Started: $($serviceStart.Count)"
    Write-Host "    Services Stopped: $($serviceStop.Count)"
    if ($serviceFailed.Count -gt 0) {
        Write-Host "    ⚠️  Service Failures: $($serviceFailed.Count)" -ForegroundColor Yellow
    }
    
    # Hardware events
    $hardwareEvents = $systemEvents | Where-Object { 
        $_.ProviderName -like "*disk*" -or 
        $_.ProviderName -like "*ntfs*" -or 
        $_.ProviderName -like "*storage*" -or
        $_.Id -in @(51, 98, 129)
    }
    
    if ($hardwareEvents.Count -gt 0) {
        Write-Host "  🔧 Hardware-Related Events: $($hardwareEvents.Count)"
        if ($hardwareEvents.Count -gt 10) {
            Write-Host "    ⚠️  High hardware event count - check system health" -ForegroundColor Yellow
            $Results.Recommendations += "High hardware event count detected - run hardware diagnostics"
        }
    }
    
    # Driver events
    $driverEvents = $systemEvents | Where-Object { 
        $_.ProviderName -like "*pnp*" -or 
        $_.ProviderName -like "*plug*" -or 
        $_.Id -in @(219, 220)
    }
    
    if ($driverEvents.Count -gt 0) {
        Write-Host "  🎛️  Driver Events: $($driverEvents.Count)"
    }
}
#endregion

#region Application Events Analysis
Write-Host "`n📱 Application Events Analysis" -ForegroundColor Yellow

$appEvents = $Results.Events | Where-Object { $_.LogName -eq "Application" }

if ($appEvents.Count -gt 0) {
    # Application errors and crashes
    $appErrors = $appEvents | Where-Object { $_.Level -in @(1, 2) }
    $appCrashes = $appEvents | Where-Object { 
        $_.Id -in @(1000, 1001, 1002) -or 
        $_.Message -like "*crash*" -or 
        $_.Message -like "*fault*" 
    }
    
    Write-Host "  💥 Application Issues:"
    Write-Host "    Application Errors: $($appErrors.Count)"
    Write-Host "    Application Crashes: $($appCrashes.Count)"
    
    if ($appCrashes.Count -gt 0) {
        $crashesByApp = $appCrashes | Group-Object { 
            if ($_.Message -match "Faulting application name: (.+?),") { 
                $matches[1] 
            } elseif ($_.Message -match "Application: (.+?)\.exe") { 
                $matches[1] + ".exe" 
            } else { 
                $_.ProviderName 
            }
        } | Sort-Object Count -Descending | Select-Object -First 5
        
        Write-Host "    🔥 Top Crashing Applications:"
        foreach ($group in $crashesByApp) {
            Write-Host "      $($group.Name): $($group.Count) crashes"
        }
    }
    
    # Windows Updates
    $updateEvents = $appEvents | Where-Object { 
        $_.ProviderName -like "*WindowsUpdateClient*" -or 
        $_.ProviderName -like "*MsiInstaller*" -or
        $_.Id -in @(19, 20, 43, 44)
    }
    
    if ($updateEvents.Count -gt 0) {
        Write-Host "  🔄 Update Activity: $($updateEvents.Count) events"
    }
}
#endregion

#region Statistics and Summary
if ($ShowStats) {
    Write-Host "`n📊 Event Statistics" -ForegroundColor Green
    
    # Events by level
    $eventsByLevel = $Results.Events | Group-Object LevelDisplayName | Sort-Object Count -Descending
    Write-Host "  📈 Events by Level:"
    foreach ($group in $eventsByLevel) {
        $icon = switch ($group.Name) {
            "Critical" { "🔴" }
            "Error" { "🟠" }
            "Warning" { "🟡" }
            "Information" { "🔵" }
            default { "⚪" }
        }
        Write-Host "    $icon $($group.Name): $($group.Count)"
    }
    
    # Events by hour
    Write-Host "`n  ⏰ Activity Timeline (Last 24 Hours):"
    $eventsByHour = $Results.Events | Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-24) } |
                    Group-Object { $_.TimeCreated.Hour } | Sort-Object Name
    
    foreach ($hour in 0..23) {
        $hourEvents = $eventsByHour | Where-Object { $_.Name -eq $hour }
        $count = if ($hourEvents) { $hourEvents.Count } else { 0 }
        $bar = "█" * [math]::Min(($count / 10), 20)
        Write-Host "    $($hour.ToString('00')):00 [$($count.ToString('000'))] $bar"
    }
    
    # Top sources
    if ($GroupBySource) {
        Write-Host "`n  🏷️  Top Event Sources:"
        $topSources = $Results.Events | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 10
        foreach ($source in $topSources) {
            Write-Host "    $($source.Name): $($source.Count) events"
        }
    }
    
    $Results.Statistics = @{
        TotalEvents = $Results.Events.Count
        EventsByLevel = $eventsByLevel
        EventsByHour = $eventsByHour
        TopSources = if ($GroupBySource) { $topSources } else { @() }
        AnalysisDuration = [math]::Round(((Get-Date) - [DateTime]$Results.Timestamp).TotalSeconds, 2)
    }
}
#endregion

#region Timeline View
if ($TimelineView) {
    Write-Host "`n📅 Event Timeline (Recent Critical Events)" -ForegroundColor Cyan
    
    $criticalEvents = $Results.Events | Where-Object { $_.Level -in @(1, 2) } | 
                     Sort-Object TimeCreated -Descending | Select-Object -First 20
    
    foreach ($event in $criticalEvents) {
        $timeStr = $event.TimeCreated.ToString("MM/dd HH:mm:ss")
        $levelIcon = if ($event.Level -eq 1) { "🔴" } else { "🟠" }
        Write-Host "  $timeStr $levelIcon [$($event.LogName)] $($event.ProviderName) - Event $($event.Id)"
        if ($Detailed) {
            $shortMessage = if ($event.Message.Length -gt 80) { 
                $event.Message.Substring(0, 80) + "..." 
            } else { 
                $event.Message 
            }
            Write-Host "    $shortMessage" -ForegroundColor Gray
        }
    }
}
#endregion

#region Recommendations
Write-Host "`n💡 Recommendations" -ForegroundColor Cyan

# Add automatic recommendations based on analysis
if ($Results.Events.Count -eq 0) {
    $Results.Recommendations += "No events found - consider adjusting search criteria or time range"
}

if ($errorEvents.Count -gt 100) {
    $Results.Recommendations += "High error count detected - review system stability"
}

if ($Results.SecurityAnalysis.SuspiciousActivity -and $Results.SecurityAnalysis.SuspiciousActivity.Count -gt 0) {
    $Results.Recommendations += "Security issues detected - review failed logon attempts"
}

if ($Results.Errors.Count -gt 0) {
    $Results.Recommendations += "Script encountered errors - ensure Administrator privileges"
}

if ($Results.Recommendations.Count -gt 0) {
    foreach ($recommendation in $Results.Recommendations) {
        Write-Host "  • $recommendation" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ✅ No immediate issues detected" -ForegroundColor Green
}
#endregion

#region Export Results
if ($ExportJson -or $ExportCsv) {
    Write-Host "`n📄 Exporting Results..." -ForegroundColor Yellow
    
    if ($ExportJson) {
        try {
            $jsonPath = "$OutputPath-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
            $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
            Write-Host "  ✅ JSON report exported to: $jsonPath" -ForegroundColor Green
        } catch {
            Write-Host "  ❌ Failed to export JSON: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    if ($ExportCsv) {
        try {
            $csvPath = "$OutputPath-events-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
            $Results.Events | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "  ✅ CSV report exported to: $csvPath" -ForegroundColor Green
        } catch {
            Write-Host "  ❌ Failed to export CSV: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}
#endregion

#region Final Summary
Write-Host "`n📋 Analysis Summary" -ForegroundColor Green
Write-Host "  🔍 Logs Analyzed: $($LogNames -join ', ')"
Write-Host "  📊 Total Events: $($Results.Events.Count)"
Write-Host "  🔴 Errors: $(($Results.Events | Where-Object { $_.Level -eq 2 }).Count)"
Write-Host "  🟡 Warnings: $(($Results.Events | Where-Object { $_.Level -eq 3 }).Count)"
Write-Host "  ⚠️  Script Errors: $($Results.Errors.Count)"
Write-Host "  ⏱️  Analysis Time: $($Results.Statistics.AnalysisDuration) seconds" -ErrorAction SilentlyContinue

if ($Results.Errors.Count -gt 0 -and $Detailed) {
    Write-Host "`n🐛 Script Errors:" -ForegroundColor Red
    foreach ($error in $Results.Errors) {
        Write-Host "  • $error" -ForegroundColor Red
    }
}

Write-Host "`n✅ Event log analysis complete!" -ForegroundColor Green
#endregion