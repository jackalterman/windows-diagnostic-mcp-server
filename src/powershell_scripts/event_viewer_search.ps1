#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Comprehensive Windows Event Viewer Search Tool
.DESCRIPTION
    Searches across ALL available Windows Event Logs for specific keywords, event IDs, or other criteria.
    This script enumerates all available logs and searches each one, providing comprehensive results.
.NOTES
    Requires Administrator privileges for Security log access
    Performance may vary based on log size and search criteria
.EXAMPLE
    .\event_viewer_search.ps1 -SearchKeyword "error" -MaxEventsPerLog 50
.EXAMPLE
    .\event_viewer_search.ps1 -EventIDs @(4624, 4625) -Hours 24 -IncludeDisabledLogs
.EXAMPLE
    .\event_viewer_search.ps1 -SearchKeyword "authentication" -Sources @("Microsoft-Windows-Security-Auditing")
#>

param(
    [string]$SearchKeyword = "",
    [int[]]$EventIDs = @(),
    [string[]]$Sources = @(),
    [string[]]$LogNames = @(),
    [int]$Hours = 24,
    [int]$Days = 0,
    [string]$StartTime = "",
    [string]$EndTime = "",
    [int]$MaxEventsPerLog = 100,
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
    [switch]$IncludeCustomLogs
)

# Initialize results object
$Results = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ComputerName = $env:COMPUTERNAME
    SearchCriteria = @{
        Keyword = $SearchKeyword
        EventIDs = $EventIDs
        Sources = $Sources
        TimeRange = @{}
        MaxEventsPerLog = $MaxEventsPerLog
    }
    LogDiscovery = @{
        TotalLogsFound = 0
        EnabledLogs = 0
        DisabledLogs = 0
        AccessibleLogs = 0
        InaccessibleLogs = 0
        LogsSearched = @()
        LogsSkipped = @()
    }
    SearchResults = @{
        TotalEventsFound = 0
        EventsByLog = @{}
        EventsByLevel = @{}
        EventsBySource = @{}
        TopEventIDs = @()
    }
    Events = @()
    Errors = @()
    Warnings = @()
    Performance = @{
        SearchDuration = 0
        LogsProcessed = 0
        AverageTimePerLog = 0
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

$Results.SearchCriteria.TimeRange = @{
    StartTime = $startDateTime.ToString("yyyy-MM-dd HH:mm:ss")
    EndTime = $endDateTime.ToString("yyyy-MM-dd HH:mm:ss")
    Duration = "$Hours hours"
}
#endregion

#region Log Discovery
$searchStartTime = Get-Date

try {
    # Get all available logs
    $allLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Sort-Object LogName
    
    $Results.LogDiscovery.TotalLogsFound = $allLogs.Count
    
    # Filter logs based on parameters
    $logsToSearch = @()
    
    foreach ($log in $allLogs) {
        $includeLog = $false
        
        # Check if specific log names are specified
        if ($LogNames.Count -gt 0) {
            if ($LogNames -contains $log.LogName) {
                $includeLog = $true
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
}
#endregion

#region Event Search
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
        
        # Get events
        $events = Get-WinEvent -FilterHashtable $filterHashtable -MaxEvents $MaxEventsPerLog -ErrorAction Stop
        
        # Apply keyword filter if specified
        if ($SearchKeyword -and $SearchKeyword.Trim() -ne "") {
            $events = $events | Where-Object { $_.Message -like "*$SearchKeyword*" }
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
            Write-Host "Searched $($log.LogName): $logEventCount events found"
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
#endregion

#region Results Processing
$Results.Events = $allEvents | Sort-Object TimeCreated -Descending
$Results.SearchResults.EventsByLog = $eventsByLog
$Results.SearchResults.EventsByLevel = $eventsByLevel
$Results.SearchResults.EventsBySource = $eventsBySource

# Get top event IDs
$Results.SearchResults.TopEventIDs = $eventIdCounts.GetEnumerator() | 
    Sort-Object Value -Descending | 
    Select-Object -First 10 | 
    ForEach-Object { @{ EventID = $_.Key; Count = $_.Value } }

# Performance metrics
$searchEndTime = Get-Date
$Results.Performance.SearchDuration = [math]::Round(($searchEndTime - $searchStartTime).TotalSeconds, 2)
$Results.Performance.LogsProcessed = $Results.LogDiscovery.LogsSearched.Count
if ($Results.Performance.LogsProcessed -gt 0) {
    $Results.Performance.AverageTimePerLog = [math]::Round($Results.Performance.SearchDuration / $Results.Performance.LogsProcessed, 2)
}
#endregion

#region Summary and Recommendations
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
#endregion

# Return results as JSON
$Results | ConvertTo-Json -Depth 10 -Compress 