# Note: This script works best with Administrator privileges for full Security log access
<#
.SYNOPSIS
    Comprehensive Windows Event Viewer Search and Analysis Tool
.DESCRIPTION
    Unified tool that combines search and analysis capabilities for Windows Event Logs.
    Can enumerate ALL available Windows event logs and search across them for keywords, 
    event IDs, or other criteria, while also providing detailed security analysis, 
    error pattern detection, and actionable recommendations.
.NOTES
    Requires Administrator privileges for Security log access
    Performance may vary based on log size and search criteria
.EXAMPLE
    .\event_viewer.ps1 -SearchKeyword "error" -MaxEventsPerLog 50 -SecurityAnalysis
.EXAMPLE
    .\event_viewer.ps1 -EventIDs @(4624, 4625) -Hours 24 -IncludeDisabledLogs -Detailed
.EXAMPLE
    .\event_viewer.ps1 -SearchKeyword "authentication" -Sources @("Microsoft-Windows-Security-Auditing") -ShowLogDiscovery
#>

param(
    # Search parameters (from event_viewer_search)
    [string]$SearchKeyword = "",
    [string]$EventIDs = "",  
    [string]$Sources = "",   
    [string]$LogNames = "",  
    [string]$Hours = "24",   
    [string]$Days = "0",     
    [string]$StartTime = "",
    [string]$EndTime = "",
    [string]$MaxEventsPerLog = "100",  
    [switch]$IncludeDisabledLogs,      
    [switch]$ErrorsOnly,               
    [switch]$WarningsOnly,             
    [switch]$CriticalOnly,             
    [switch]$InformationOnly,          
    [switch]$Verbose,                  
    [switch]$ShowLogDiscovery,         
    [switch]$SkipSecurityLog,          
    [switch]$IncludeSystemLogs,        
    [switch]$IncludeApplicationLogs,   
    [switch]$IncludeCustomLogs,        
    
    # Analyzer parameters (from event_viewer_analyzer)
    [string]$SearchTerms = "",  # Changed to string for better handling
    [switch]$SecurityAnalysis,          # Changed to switch for boolean handling
    [switch]$Detailed,                  # Changed to switch for boolean handling
    [switch]$ExportJson,                # Changed to switch for boolean handling
    [switch]$ExportCsv,                 # Changed to switch for boolean handling
    [string]$OutputPath = ".\eventlog-analysis",
    [string]$MaxEvents = "1000",        # Changed to string for better handling
    [switch]$ShowStats,                 # Changed to switch for boolean handling
    [switch]$GroupBySource,             # Changed to switch for boolean handling
    [switch]$TimelineView,              # Changed to switch for boolean handling
    [switch]$Debug                      # Changed to switch for boolean handling
)

# Basic script validation - ensure we're running
$isAdmin = [Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544'

if ($Debug) {
    Write-Error "=== SCRIPT STARTED ==="
    Write-Error "PowerShell version: $($PSVersionTable.PSVersion)"
    Write-Error "Running as Administrator: $isAdmin"
}

# Check for Administrator privileges and adjust behavior accordingly
if (-not $isAdmin) {
    if ($Debug) {
        Write-Error "WARNING: Not running as Administrator - Security log access will be limited"
    }
    # Skip Security log by default if not running as Administrator
    if (-not $SkipSecurityLog) {
        $SkipSecurityLog = $true
        if ($Debug) {
            Write-Error "Auto-skipping Security log due to lack of Administrator privileges"
        }
    }
}

#region Parameter Conversion and Validation
# Convert string parameters to appropriate types
try {
    # Convert numeric parameters
    $Hours = [int]$Hours
    $Days = [int]$Days
    $MaxEventsPerLog = [int]$MaxEventsPerLog
    $MaxEvents = [int]$MaxEvents
    
    # Convert array parameters
    $EventIDs = if ($EventIDs -and $EventIDs.Trim() -ne "") { 
        $EventIDs.Split(',') | ForEach-Object { [int]$_.Trim() } 
    } else { @() }
    
    $Sources = if ($Sources -and $Sources.Trim() -ne "") { 
        $Sources.Split(',') | ForEach-Object { $_.Trim() } 
    } else { @() }
    
    $LogNames = if ($LogNames -and $LogNames.Trim() -ne "") { 
        $LogNames.Split(',') | ForEach-Object { $_.Trim() } 
    } else { @() }
    
    $SearchTerms = if ($SearchTerms -and $SearchTerms.Trim() -ne "") { 
        $SearchTerms.Split(',') | ForEach-Object { $_.Trim() } 
    } else { @() }
    
} catch {
    $errorMessage = "Error converting parameters: $($_.Exception.Message)"
    Write-Error $errorMessage
}

# Improve default behavior to be more likely to return results
if ($Debug) {
    Write-Error "Before default behavior - LogNames: $($LogNames -join ',') (Count: $($LogNames.Count))"
}

if (-not $SearchKeyword -and $EventIDs.Count -eq 0 -and $Sources.Count -eq 0 -and $LogNames.Count -eq 0) {
    # Default to include System and Application logs if no specific logs specified
    if ($LogNames.Count -eq 0) {
        $LogNames = @("System", "Application")
        if ($Debug) {
            Write-Error "Setting default logs to: System, Application"
        }
    }
    
    # If no time criteria specified, extend the time window
    if ($Hours -eq 24 -and $Days -eq 0 -and -not $StartTime -and -not $EndTime) {
        $Hours = 168  # 7 days instead of 1 day
        if ($Debug) {
            Write-Error "Extended time window to 7 days for better results"
        }
    }
}

if ($Debug) {
    Write-Error "After default behavior - LogNames: $($LogNames -join ',') (Count: $($LogNames.Count))"
}
#endregion

# Initialize unified results object
$Results = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ComputerName = $env:COMPUTERNAME
    
    # Analysis period (from analyzer)
    AnalysisPeriod = @{}
    
    # Search criteria (from search)
    SearchCriteria = @{
        Keyword = $SearchKeyword
        EventIDs = $EventIDs
        Sources = $Sources
        TimeRange = @{}
        MaxEventsPerLog = $MaxEventsPerLog
    }
    
    # Log discovery (from search) - enhanced
    LogDiscovery = @{
        TotalLogsFound = 0
        EnabledLogs = 0
        DisabledLogs = 0
        AccessibleLogs = 0
        InaccessibleLogs = 0
        LogsSearched = @()
        LogsSkipped = @()
    }
    
    # Log summary (from analyzer)
    LogSummary = @{}
    
    # Search results (from search)
    SearchResults = @{
        TotalEventsFound = 0
        EventsByLog = @{}
        EventsByLevel = @{}
        EventsBySource = @{}
        TopEventIDs = @()
    }
    
    # Analysis features (from analyzer)
    SecurityAnalysis = @{}
    ErrorPatterns = @{}
    Statistics = @{}
    Recommendations = @()
    
    # Events (from search)
    Events = @()
    
    # Performance (from search)
    Performance = @{
        SearchDuration = 0
        LogsProcessed = 0
        AverageTimePerLog = 0
    }
    
    # Errors and warnings (from search)
    Errors = @()
    Warnings = @()
}

# Debug output if enabled - after Results object is created
if ($Debug) {
    $Results.DebugInfo = @{
        ParameterValues = @{
            SearchKeyword = $SearchKeyword
            EventIDs = $EventIDs
            Sources = $Sources
            LogNames = $LogNames
            Hours = $Hours
            Days = $Days
            MaxEventsPerLog = $MaxEventsPerLog
            SecurityAnalysis = $SecurityAnalysis
            Verbose = $Verbose
        }
        ExecutionSteps = @()
    }
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

$Results.SearchCriteria.TimeRange = @{
    StartTime = $startDateTime.ToString("yyyy-MM-dd HH:mm:ss")
    EndTime = $endDateTime.ToString("yyyy-MM-dd HH:mm:ss")
    Duration = "$Hours hours"
}
#endregion

#region Log Discovery and Summary
$searchStartTime = Get-Date

try {
    # Get all available logs
    $allLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Sort-Object LogName
    
    $Results.LogDiscovery.TotalLogsFound = $allLogs.Count
    
    if ($Debug) {
        $Results.DebugInfo.ExecutionSteps += "Found $($allLogs.Count) total logs"
    }
    
    # Filter logs based on parameters
    $logsToSearch = @()
    
    foreach ($log in $allLogs) {
        $includeLog = $false
        
        if ($Debug) {
            $Results.DebugInfo.ExecutionSteps += "Checking log: $($log.LogName) - LogNames: $($LogNames -join ',')"
        }
        
        # Check if specific log names are specified
        if ($LogNames.Count -gt 0) {
            if ($LogNames -contains $log.LogName) {
                $includeLog = $true
                if ($Debug) {
                    $Results.DebugInfo.ExecutionSteps += "  -> INCLUDED (matches LogNames)"
                }
            }
        } else {
            # Apply category filters
            if ($IncludeSystemLogs -and $log.LogName -in @("System", "Security", "Application", "Setup")) {
                $includeLog = $true
            }
            elseif ($IncludeApplicationLogs -and $log.LogName -like "*Application*") {
                $includeLog = $true
            }
            elseif ($IncludeCustomLogs -and $log.LogName -notlike "*System*" -and $log.LogName -notlike "*Security*" -and $log.LogName -notlike "*Application*") {
                $includeLog = $true
            }
            elseif (-not $IncludeSystemLogs -and -not $IncludeApplicationLogs -and -not $IncludeCustomLogs) {
                # Default: include all logs
                $includeLog = $true
            }
        }
        
        # Skip Security log if specified
        if ($SkipSecurityLog -and $log.LogName -eq "Security") {
            $includeLog = $false
        }
        
        # Check if log is enabled (unless IncludeDisabledLogs is specified)
        if ($includeLog -and -not $IncludeDisabledLogs -and -not $log.IsEnabled) {
            $includeLog = $false
            $Results.LogDiscovery.LogsSkipped += @{
                LogName = $log.LogName
                Reason = "Disabled"
            }
        }
        
        if ($includeLog) {
            $logsToSearch += $log
        }
        
        # Update statistics
        if ($log.IsEnabled) {
            $Results.LogDiscovery.EnabledLogs++
        } else {
            $Results.LogDiscovery.DisabledLogs++
        }
        
        # Build log summary (from analyzer)
        $Results.LogSummary[$log.LogName] = @{
            RecordCount = $log.RecordCount
            FileSize = [math]::Round($log.FileSize / 1MB, 2)
            LastWriteTime = $log.LastWriteTime
            IsEnabled = $log.IsEnabled
            Available = $true
        }
    }
    
    if ($Debug) {
        $Results.DebugInfo.ExecutionSteps += "Selected $($logsToSearch.Count) logs for searching"
        $Results.DebugInfo.ExecutionSteps += "Logs to search: $($logsToSearch.LogName -join ', ')"
    }
    
    if ($ShowLogDiscovery) {
        $Results.LogDiscovery.AllLogs = $allLogs | ForEach-Object { @{
            LogName = $_.LogName
            IsEnabled = $_.IsEnabled
            RecordCount = $_.RecordCount
            FileSize = [math]::Round($_.FileSize / 1MB, 2)
            LastWriteTime = $_.LastWriteTime
        }}
    }
    
} catch {
    $errorMessage = "Error during log discovery: $($_.Exception.Message)"
    $Results.Errors += $errorMessage
    if ($Debug) {
        $Results.DebugInfo.ExecutionSteps += "ERROR: $errorMessage"
    }
}
#endregion

#region Event Search and Collection
$allEvents = @()
$eventsByLog = @{}
$eventsByLevel = @{}
$eventsBySource = @{}
$eventIdCounts = @{}

foreach ($log in $logsToSearch) {
    $logStartTime = Get-Date
    
    try {
        # Build filter hashtable
        $filterHashtable = @{
            LogName = $log.LogName
            StartTime = $startDateTime
            EndTime = $endDateTime
        }
        
        # Add level filters
        if ($ErrorsOnly) { $filterHashtable.Level = 2 }
        elseif ($WarningsOnly) { $filterHashtable.Level = 3 }
        elseif ($CriticalOnly) { $filterHashtable.Level = 1 }
        elseif ($InformationOnly) { $filterHashtable.Level = 4 }
        
        # Add event ID filter
        if ($EventIDs.Count -gt 0) { $filterHashtable.ID = $EventIDs }
        
        # Add source filter
        if ($Sources.Count -gt 0) { $filterHashtable.ProviderName = $Sources }
        
        if ($Debug) {
            $Results.DebugInfo.ExecutionSteps += "Searching log: $($log.LogName)"
            $Results.DebugInfo.ExecutionSteps += "Filter: $($filterHashtable | ConvertTo-Json -Compress)"
        }
        
        # Get events
        $events = Get-WinEvent -FilterHashtable $filterHashtable -MaxEvents $MaxEventsPerLog -ErrorAction Stop
        
        # Apply keyword filter if specified
        if ($SearchKeyword -and $SearchKeyword.Trim() -ne "") {
            $events = $events | Where-Object { $_.Message -like "*$SearchKeyword*" }
        }
        
        # Apply search terms filter (from analyzer)
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
        
        $logEventCount = $events.Count
        $Results.SearchResults.TotalEventsFound += $logEventCount
        
        # Process events
        foreach ($event in $events) {
            $eventObj = @{
                TimeCreated = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
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
            
            # Update statistics
            if (-not $eventsByLog.ContainsKey($event.LogName)) {
                $eventsByLog[$event.LogName] = 0
            }
            $eventsByLog[$event.LogName]++
            
            if (-not $eventsByLevel.ContainsKey($event.LevelDisplayName)) {
                $eventsByLevel[$event.LevelDisplayName] = 0
            }
            $eventsByLevel[$event.LevelDisplayName]++
            
            if (-not $eventsBySource.ContainsKey($event.ProviderName)) {
                $eventsBySource[$event.ProviderName] = 0
            }
            $eventsBySource[$event.ProviderName]++
            
            if (-not $eventIdCounts.ContainsKey($event.Id)) {
                $eventIdCounts[$event.Id] = 0
            }
            $eventIdCounts[$event.Id]++
        }
        
        $Results.LogDiscovery.AccessibleLogs++
        $Results.LogDiscovery.LogsSearched += @{
            LogName = $log.LogName
            EventsFound = $logEventCount
            SearchTime = [math]::Round(((Get-Date) - $logStartTime).TotalMilliseconds, 2)
        }
        
        if ($Verbose) {
            $Results.DebugInfo.ExecutionSteps += "Searched $($log.LogName): $logEventCount events found"
        }
        
    } catch {
        $errorMessage = "Error searching log $($log.LogName): $($_.Exception.Message)"
        $Results.Errors += $errorMessage
        $Results.LogDiscovery.InaccessibleLogs++
        $Results.LogDiscovery.LogsSkipped += @{
            LogName = $log.LogName
            Reason = "Access Denied"
            Error = $_.Exception.Message
        }
    }
}

$Results.Events = $allEvents | Sort-Object TimeCreated -Descending
$Results.SearchResults.EventsByLog = $eventsByLog
$Results.SearchResults.EventsByLevel = $eventsByLevel
$Results.SearchResults.EventsBySource = $eventsBySource

# Get top event IDs
$Results.SearchResults.TopEventIDs = $eventIdCounts.GetEnumerator() | 
    Sort-Object Value -Descending | 
    Select-Object -First 10 | 
    ForEach-Object { @{ EventID = $_.Key; Count = $_.Value } }
#endregion

#region Security Analysis (from analyzer)
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

#region Error Pattern Analysis (from analyzer)
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

#region System Events Analysis (from analyzer)
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

#region Performance Metrics
$searchEndTime = Get-Date
$Results.Performance.SearchDuration = [math]::Round(($searchEndTime - $searchStartTime).TotalSeconds, 2)
$Results.Performance.LogsProcessed = $Results.LogDiscovery.LogsSearched.Count
if ($Results.Performance.LogsProcessed -gt 0) {
    $Results.Performance.AverageTimePerLog = [math]::Round($Results.Performance.SearchDuration / $Results.Performance.LogsProcessed, 2)
}

$Results.Statistics.AnalysisDuration = [math]::Round(((Get-Date) - [DateTime]$Results.Timestamp).TotalSeconds, 2)
#endregion

#region Recommendations and Summary
if ($Results.SearchResults.TotalEventsFound -eq 0) {
    $Results.Warnings += "No events found matching the search criteria. Consider:"
    $Results.Warnings += "- Expanding the time range"
    $Results.Warnings += "- Using broader search terms"
    $Results.Warnings += "- Checking if logs are enabled"
    $Results.Warnings += "- Verifying administrator privileges"
}

if ($Results.LogDiscovery.InaccessibleLogs -gt 0) {
    $Results.Warnings += "$($Results.LogDiscovery.InaccessibleLogs) logs were inaccessible. Run as Administrator for full access."
}

if ($Results.Errors.Count -gt 0) {
    $Results.Warnings += "Some errors occurred during search. Check the 'Errors' property for details."
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

#region Export Options (from analyzer)
if ($ExportJson -or $ExportCsv) {
    try {
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        
        if ($ExportJson) {
            $jsonPath = Join-Path $OutputPath "eventlog-analysis_$timestamp.json"
            $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
            $Results.Recommendations += "Results exported to JSON: $jsonPath"
        }
        
        if ($ExportCsv) {
            $csvPath = Join-Path $OutputPath "eventlog-events_$timestamp.csv"
            $Results.Events | Export-Csv -Path $csvPath -NoTypeInformation
            $Results.Recommendations += "Events exported to CSV: $csvPath"
        }
    } catch {
        $errorMessage = "Error exporting results: $($_.Exception.Message)"
        $Results.Errors += $errorMessage
    }
}
#endregion

#region Final Debug and Error Summary
if ($Debug) {
    $Results.DebugInfo.ExecutionSteps += "=== FINAL SUMMARY ==="
    $Results.DebugInfo.ExecutionSteps += "Total events found: $($Results.SearchResults.TotalEventsFound)"
    $Results.DebugInfo.ExecutionSteps += "Logs searched: $($Results.LogDiscovery.LogsSearched.Count)"
    $Results.DebugInfo.ExecutionSteps += "Logs skipped: $($Results.LogDiscovery.LogsSkipped.Count)"
    $Results.DebugInfo.ExecutionSteps += "Errors encountered: $($Results.Errors.Count)"
    $Results.DebugInfo.ExecutionSteps += "Warnings: $($Results.Warnings.Count)"
    $Results.DebugInfo.ExecutionSteps += "Recommendations: $($Results.Recommendations.Count)"
    $Results.DebugInfo.ExecutionSteps += "====================="
}

# Ensure we have some basic results even if no events found
if ($Results.SearchResults.TotalEventsFound -eq 0) {
    $Results.Warnings += "No events found matching the search criteria. This could be due to:"
    $Results.Warnings += "- Limited time range (try extending Hours or Days)"
    $Results.Warnings += "- Specific filters being too restrictive"
    $Results.Warnings += "- Logs being disabled or inaccessible"
    $Results.Warnings += "- System having very few recent events"
    
    if ($Debug) {
        $Results.DebugInfo.ExecutionSteps += "WARNING: No events found - check the warnings in the output"
    }
}

# Add execution summary
$Results.Statistics.ExecutionSummary = @{
    ParametersProcessed = $true
    LogDiscoveryCompleted = $true
    EventSearchCompleted = $true
    AnalysisCompleted = $true
    OutputGenerated = $true
}
#endregion

# Return unified results as JSON
try {
    # Add basic validation to ensure we have a valid result
    if (-not $Results) {
        throw "Results object is null or undefined"
    }
    
    # Ensure we have at least basic structure
    if (-not $Results.Timestamp) {
        $Results.Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    if (-not $Results.ComputerName) {
        $Results.ComputerName = $env:COMPUTERNAME
    }
    
    $jsonOutput = $Results | ConvertTo-Json -Depth 10 -Compress
    if ($Debug) {
        $Results.DebugInfo.ExecutionSteps += "JSON output length: $($jsonOutput.Length) characters"
    }
    
    # Validate JSON output
    if (-not $jsonOutput -or $jsonOutput.Trim() -eq "") {
        throw "Generated JSON output is empty"
    }
    
    $jsonOutput
} catch {
    $errorMessage = "Error generating JSON output: $($_.Exception.Message)"
    Write-Error $errorMessage
    
    # Return a minimal error response
    $minimalResponse = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ComputerName = $env:COMPUTERNAME
        Errors = @($errorMessage)
        Warnings = @("Failed to generate complete output")
        Events = @()
        SearchResults = @{ TotalEventsFound = 0 }
        DebugInfo = @{
            ParameterValues = @{
                SearchKeyword = $SearchKeyword
                EventIDs = $EventIDs
                Sources = $Sources
                LogNames = $LogNames
                Hours = $Hours
                Days = $Days
                MaxEventsPerLog = $MaxEventsPerLog
                SecurityAnalysis = $SecurityAnalysis
                Verbose = $Verbose
            }
            ExecutionSteps = @("Script failed during execution", "Error: $errorMessage")
        }
    }
    
    try {
        $minimalResponse | ConvertTo-Json -Compress
    } catch {
        # Last resort - return a simple string
        '{"error": "Failed to generate any output", "timestamp": "' + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + '"}'
    }
}
