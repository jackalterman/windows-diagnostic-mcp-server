#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Comprehensive Windows Event Log Analyzer and Search Tool
.DESCRIPTION
    Searches, filters, and analyzes Windows Event Logs across Security, Application, System, and custom logs.
    This script is designed to be called from other applications and will output a JSON object containing the analysis.
.NOTES
    Requires Administrator privileges for Security log access
    Performance may vary based on log size and search criteria
.EXAMPLE
    .\event_viewer_analyzer.ps1 -LogNames "Security","System" -Hours 24 -ErrorsOnly
.EXAMPLE
    .\event_viewer_analyzer.ps1 -SearchTerms "logon","authentication" -Detailed
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

#region Time Range Calculation
if ($Days -gt 0) { $Hours = $Days * 24 }

if ($StartTime -and $EndTime) {
    try {
        $startDateTime = [DateTime]::Parse($StartTime)
        $endDateTime = [DateTime]::Parse($EndTime)
    } catch {
        $errorMessage = "Invalid date format. Using default time range."
        $Results.Errors += $errorMessage
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
#endregion

#region Log Availability Check
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
    } else {
        $logStats[$logName] = @{ Available = $false }
    }
}

$Results.LogSummary = $logStats
#endregion

#region Event Search and Collection
$allEvents = @()
$totalEventsFound = 0

foreach ($logName in $LogNames) {
    if (-not ($logStats[$logName] -and $logStats[$logName].Available)) { continue }

    try {
        $filterHashtable = @{
            LogName = $logName
            StartTime = $startDateTime
            EndTime = $endDateTime
        }

        if ($ErrorsOnly) { $filterHashtable.Level = 2 }
        elseif ($WarningsOnly) { $filterHashtable.Level = 3 }
        elseif ($CriticalOnly) { $filterHashtable.Level = 1 }

        if ($EventIDs.Count -gt 0) { $filterHashtable.ID = $EventIDs }

        $events = Get-WinEvent -FilterHashtable $filterHashtable -MaxEvents $MaxEvents -ErrorAction Stop

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
        $errorMessage = "Error accessing ${logName}: $($_.Exception.Message)"
        $Results.Errors += $errorMessage
    }
}

$Results.Events = $allEvents | Sort-Object TimeCreated -Descending
#endregion

#region Security Analysis
if ($SecurityAnalysis -or "Security" -in $LogNames) {
    $securityEvents = $Results.Events | Where-Object { $_.LogName -eq "Security" }

    if ($securityEvents) {
        $secAnalysis = @{
            LogonEvents = @{}
            FailedLogons = @{}
            AccountLockouts = @()
            PrivilegeUse = @()
            PolicyChanges = @()
            SuspiciousActivity = @()
        }

        $logonSuccess = $securityEvents | Where-Object { $_.Id -eq 4624 }
        $logonFailure = $securityEvents | Where-Object { $_.Id -eq 4625 }
        $logoff = $securityEvents | Where-Object { $_.Id -in @(4634, 4647) }
        $explicitLogon = $securityEvents | Where-Object { $_.Id -eq 4648 }

        $secAnalysis.LogonEvents = @{
            Successful = $logonSuccess.Count
            Failed = $logonFailure.Count
            Logoffs = $logoff.Count
            ExplicitCredentialUse = $explicitLogon.Count
        }

        $accountLockouts = $securityEvents | Where-Object { $_.Id -eq 4740 }
        if ($accountLockouts) {
            $secAnalysis.AccountLockouts = $accountLockouts
        }

        if ($logonFailure.Count -gt 0) {
            $failedLogonsByUser = $logonFailure | Group-Object {
                if ($_.Message -match "Account Name:\s+(.+)") { $matches[1].Trim() } else { "Unknown" }
            } | Sort-Object Count -Descending | Select-Object -First 5

            $secAnalysis.FailedLogons = $failedLogonsByUser | ForEach-Object { @{ Account = $_.Name; Attempts = $_.Count } }

            foreach ($group in $failedLogonsByUser) {
                if ($group.Count -gt 10) {
                    $secAnalysis.SuspiciousActivity += "High failed logon attempts for user: $($group.Name) ($($group.Count) attempts)"
                }
            }
        }

        $privilegeUse = $securityEvents | Where-Object { $_.Id -in @(4672, 4673, 4674) }
        if ($privilegeUse) {
            $secAnalysis.PrivilegeUse = $privilegeUse
        }

        $policyChanges = $securityEvents | Where-Object { $_.Id -in @(4719, 4902, 4904, 4905, 4906, 4907, 4912) }
        if ($policyChanges) {
            $secAnalysis.PolicyChanges = $policyChanges
        }

        $Results.SecurityAnalysis = $secAnalysis
    }
}
#endregion

#region Error Pattern Analysis
$errorEvents = $Results.Events | Where-Object { $_.Level -in @(1, 2) }
$warningEvents = $Results.Events | Where-Object { $_.Level -eq 3 }

if ($errorEvents.Count -gt 0) {
    $errorsByEventId = $errorEvents | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10
    $errorsBySource = $errorEvents | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 10
    $recentErrors = $errorEvents | Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-1) }

    if ($recentErrors.Count -gt 20) {
        $Results.Recommendations += "Investigate high error rate - $($recentErrors.Count) errors in the last hour"
    }

    $Results.ErrorPatterns = @{
        TotalErrors = $errorEvents.Count
        TotalWarnings = $warningEvents.Count
        TopErrorEventIds = $errorsByEventId | ForEach-Object { @{ ID = $_.Name; Count = $_.Count } }
        TopErrorSources = $errorsBySource | ForEach-Object { @{ Source = $_.Name; Count = $_.Count } }
        RecentErrorCount = $recentErrors.Count
    }
}
#endregion

#region System Events Analysis
$systemEvents = $Results.Events | Where-Object { $_.LogName -eq "System" }

if ($systemEvents.Count -gt 0) {
    $unexpectedShutdowns = $systemEvents | Where-Object { $_.Id -eq 6008 }
    if ($unexpectedShutdowns.Count -gt 0) {
        $Results.Recommendations += "Investigate $($unexpectedShutdowns.Count) unexpected shutdowns - possible hardware or power issues"
    }

    $hardwareEvents = $systemEvents | Where-Object {
        $_.ProviderName -like "*disk*" -or
        $_.ProviderName -like "*ntfs*" -or
        $_.ProviderName -like "*storage*" -or
        $_.Id -in @(51, 98, 129)
    }
    if ($hardwareEvents.Count -gt 10) {
        $Results.Recommendations += "High hardware event count ($($hardwareEvents.Count)) detected - run hardware diagnostics"
    }
}
#endregion

#region Recommendations
if ($Results.Events.Count -eq 0) {
    $Results.Recommendations += "No events found - consider adjusting search criteria or time range"
}

if ($errorEvents.Count -gt 100) {
    $Results.Recommendations += "High error count ($($errorEvents.Count)) detected - review system stability"
}

if ($Results.SecurityAnalysis.SuspiciousActivity -and $Results.SecurityAnalysis.SuspiciousActivity.Count -gt 0) {
    $Results.Recommendations += "Security issues detected - review failed logon attempts"
}

if ($Results.Errors.Count -gt 0) {
    $Results.Recommendations += "Script encountered errors during execution. Check the 'Errors' property for details. Ensure Administrator privileges."
}
#endregion

#region Final Output
$Results.Statistics.AnalysisDuration = [math]::Round(((Get-Date) - [DateTime]$Results.Timestamp).TotalSeconds, 2)
$Results | ConvertTo-Json -Depth 5 -Compress
#endregion
