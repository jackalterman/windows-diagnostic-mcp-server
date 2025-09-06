[CmdletBinding()]
param(
    # Search Criteria
    [string]$SearchKeyword = "",
    [string]$EventIDs = "",
    [string]$Sources = "",
    [string]$LogNames = "",
    [string]$SearchTerms = "",
    
    # Time Range
    [string]$Hours = "24",
    [string]$Days = "",
    [string]$StartTime = "",
    [string]$EndTime = "",
    
    # Filtering and Selection
    [string]$MaxEventsPerLog = "100",
    [switch]$IncludeDisabledLogs,
    [switch]$ErrorsOnly,
    [switch]$WarningsOnly,
    [switch]$CriticalOnly,
    [switch]$InformationOnly,
    [switch]$SkipSecurityLog,
    [switch]$IncludeSystemLogs,
    [switch]$IncludeApplicationLogs,
    [switch]$IncludeCustomLogs,
    
    # Deep Analysis Switches (separate from search terms)
    [switch]$Detailed,
    [switch]$DeepSearch,

    # Analysis and Output
    [switch]$SecurityAnalysis,
    [switch]$ExportJson,
    [switch]$ExportCsv,
    [string]$OutputPath = ".\eventlog-analysis",
    [switch]$ShowProgress
)

# Initialize result object
$result = @{
    Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
    ComputerName = $env:COMPUTERNAME
    AnalysisPeriod = @{}
    SearchCriteria = @{}
    LogDiscovery = @{}
    LogSummary = @{}
    SearchResults = @{}
    SecurityAnalysis = @{}
    ErrorPatterns = @{}
    Statistics = @{
        StartTime = Get-Date
        SearchDuration = 0
        LogsProcessed = 0
        EventsFound = 0
    }
    Recommendations = @()
    Events = @()
    Errors = @()
    Warnings = @()
}

# Default limits for event categories in standard mode
$defaultLimits = @{
    ErrorsPerLog = 10
    WarningsPerLog = 5
    CriticalPerLog = 20
    SuccessfulLogons = 10
    FailedLogons = 20
    AccountLockouts = 10
    Restarts = 5
    ServiceEvents = 10
    Updates = 10
    ApplicationCrashes = 10
    HardwareErrors = 10
}

try {
    # Determine if we're in deep search mode (separate from search terms)
    $isDeepSearch = $Detailed -or $DeepSearch
    
    # Calculate time range
    [DateTime]$endTime = Get-Date
    if (![string]::IsNullOrEmpty($EndTime)) {
        $endTime = [DateTime](Get-Date $EndTime)
    }
    
    # Default to 24 hours if no time parameters specified
    [int]$hoursBack = 24
    if (![string]::IsNullOrEmpty($Hours)) {
        $hoursBack = [int]$Hours
    }
    
    [DateTime]$startTime = $endTime.AddHours(-$hoursBack)
    
    # Override with days if specified
    if (![string]::IsNullOrEmpty($Days)) {
        $startTime = $endTime.AddDays(-[int]$Days)
    }
    
    # Override with specific start time if provided
    if (![string]::IsNullOrEmpty($StartTime)) {
        $startTime = [DateTime](Get-Date $StartTime)
    }
    
    $result.AnalysisPeriod = @{
        StartTime = $startTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        EndTime = $endTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        Duration = ($endTime - $startTime).ToString()
    }
    
    $result.SearchCriteria = @{
        SearchKeyword = $SearchKeyword
        EventIDs = $EventIDs
        Sources = $Sources
        LogNames = $LogNames
        SearchTerms = $SearchTerms
        MaxEventsPerLog = $MaxEventsPerLog
        DeepSearch = $isDeepSearch
        HasCustomSearch = (![string]::IsNullOrEmpty($SearchKeyword) -or ![string]::IsNullOrEmpty($SearchTerms) -or ![string]::IsNullOrEmpty($EventIDs))
    }
    
    # Determine which logs to search
    $logsToSearch = @()
    if ($isDeepSearch) {
        # Deep search: get all available logs
        Write-Error "Deep search mode: Discovering all available logs..." -ErrorAction Continue
        $allLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue
        $logsToSearch = $allLogs | Where-Object { $_.RecordCount -gt 0 -or $IncludeDisabledLogs }
    } else {
        # Default search: focus on key system logs
        $keyLogs = @('System', 'Application', 'Security', 'Setup')
        foreach ($logName in $keyLogs) {
            if ($SkipSecurityLog -and $logName -eq 'Security') { continue }
            try {
                $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
                if ($log.RecordCount -gt 0) {
                    $logsToSearch += $log
                }
            } catch {
                $errorMsg = if ($logName -eq 'Security') {
                    "Security log requires Administrator privileges. Run as Administrator for full security analysis."
                } else {
                    "Could not access log '$logName': $($_.Exception.Message)"
                }
                Write-Error $errorMsg -ErrorAction Continue
                $result.Warnings += $errorMsg
            }
        }
    }
    
    $result.LogDiscovery = @{
        TotalLogsAvailable = (Get-WinEvent -ListLog * -ErrorAction SilentlyContinue).Count
        LogsToSearch = $logsToSearch.Count
        SearchMode = if ($isDeepSearch) { "Deep" } else { "Default" }
        LogsSearched = $logsToSearch | ForEach-Object { $_.LogName }
    }
    
    # Define important event IDs for default search
    $importantEventIDs = @{
        # System Events
        Restart = @(1074, 6005, 6006, 6008, 6009, 6013)
        Shutdown = @(1074, 6006, 6008)
        ServiceStart = @(7035, 7036)
        ServiceStop = @(7034, 7035, 7036)
        Updates = @(19, 20, 21, 22, 43, 44)
        HardwareErrors = @(6008, 41, 1001, 1003, 1033)
        ApplicationCrash = @(1000, 1001, 1002)
        
        # Security Events  
        SuccessfulLogon = @(4624, 4625, 4634, 4647)
        FailedLogon = @(4625, 4771, 4776, 529, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539)
        AccountLockout = @(4740, 4767, 644)
        PrivilegeUse = @(4672, 4673, 4674)
        
        # Critical Errors
        SystemCritical = @(41, 6008, 1001, 1003)
        ApplicationError = @(1000, 1001, 1002)
        KernelPower = @(41, 42, 109)
    }
    
    # Initialize event categories
    $eventCategories = @{
        Errors = @()
        Warnings = @()
        Critical = @()
        Information = @()
        SecurityEvents = @{
            SuccessfulLogons = @()
            FailedLogons = @()
            AccountLockouts = @()
            PrivilegeUse = @()
        }
        SystemEvents = @{
            Restarts = @()
            Shutdowns = @()
            ServiceEvents = @()
            Updates = @()
            HardwareErrors = @()
            ApplicationCrashes = @()
        }
    }
    
    # Search each log
    $allEvents = @()
    $logSummary = @{}
    
    foreach ($log in $logsToSearch) {
        try {
            if ($ShowProgress) {
                Write-Error "Processing log: $($log.LogName)" -ErrorAction Continue
            }
            $result.Statistics.LogsProcessed++
            
            # Get log summary info
            $logSummary[$log.LogName] = @{
                RecordCount = $log.RecordCount
                FileSize = $log.FileSize
                LastWriteTime = if ($log.LastWriteTime) { $log.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") } else { $null }
                IsEnabled = $log.IsEnabled
            }
            
            # Build filter hash for this log
            $filterHash = @{
                LogName = $log.LogName
                StartTime = $startTime
                EndTime = $endTime
            }
            
            # Add specific filters if provided
            if (![string]::IsNullOrEmpty($EventIDs)) {
                $eventIDArray = $EventIDs -split ',' | ForEach-Object { [int]$_.Trim() }
                $filterHash.ID = $eventIDArray
            }
            
            # Determine max events for this log
            $maxEvents = [int]$MaxEventsPerLog
            if (!$isDeepSearch) {
                # In default mode, limit events more aggressively
                $maxEvents = [Math]::Min($maxEvents, 50)
            }
            
            # Get events from this log
            $events = @()
            try {
                $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents $maxEvents -ErrorAction Stop
            } catch {
                if ($_.Exception.Message -notlike "*No events were found*") {
                    Write-Error "Error reading from log '$($log.LogName)': $($_.Exception.Message)" -ErrorAction Continue
                    $result.Errors += "Error reading from log '$($log.LogName)': $($_.Exception.Message)"
                }
                continue
            }
            
            # Filter events based on search criteria if provided
            if (![string]::IsNullOrEmpty($SearchKeyword)) {
                $events = $events | Where-Object { $_.Message -like "*$SearchKeyword*" }
            }
            
            if (![string]::IsNullOrEmpty($SearchTerms)) {
                $searchTermsArray = $SearchTerms -split ',' | ForEach-Object { $_.Trim() }
                $events = $events | Where-Object { 
                    $message = $_.Message
                    $found = $false
                    foreach ($term in $searchTermsArray) {
                        if ($message -like "*$term*") {
                            $found = $true
                            break
                        }
                    }
                    $found
                }
            }
            
            # Process events and categorize them
            foreach ($event in $events) {
                $result.Statistics.EventsFound++
                
                # Create standardized event object
                $eventObj = @{
                    TimeCreated = $event.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    Id = $event.Id
                    Level = $event.Level
                    LevelDisplayName = $event.LevelDisplayName
                    LogName = $event.LogName
                    ProviderName = $event.ProviderName
                    Message = $event.Message
                    ProcessId = $event.ProcessId
                    ThreadId = $event.ThreadId
                    UserId = if ($event.UserId) { $event.UserId.Value } else { $null }
                    ActivityId = if ($event.ActivityId) { $event.ActivityId.ToString() } else { $null }
                    Keywords = $event.Keywords
                    TaskDisplayName = $event.TaskDisplayName
                }
                
                # Add to all events collection
                $allEvents += $eventObj
                
                # Categorize events for default analysis
                if (!$isDeepSearch) {
                    switch ($event.Level) {
                        1 { # Critical
                            if ($eventCategories.Critical.Count -lt $defaultLimits.CriticalPerLog) {
                                $eventCategories.Critical += $eventObj
                            }
                        }
                        2 { # Error
                            if ($eventCategories.Errors.Count -lt $defaultLimits.ErrorsPerLog) {
                                $eventCategories.Errors += $eventObj
                            }
                        }
                        3 { # Warning
                            if ($eventCategories.Warnings.Count -lt $defaultLimits.WarningsPerLog) {
                                $eventCategories.Warnings += $eventObj
                            }
                        }
                        4 { # Information
                            # Only collect specific informational events in default mode
                            if ($event.Id -in ($importantEventIDs.SuccessfulLogon + $importantEventIDs.Restart + $importantEventIDs.Updates)) {
                                $eventCategories.Information += $eventObj
                            }
                        }
                    }
                    
                    # Categorize by event type
                    if ($event.Id -in $importantEventIDs.SuccessfulLogon -and $eventCategories.SecurityEvents.SuccessfulLogons.Count -lt $defaultLimits.SuccessfulLogons) {
                        $eventCategories.SecurityEvents.SuccessfulLogons += $eventObj
                    }
                    if ($event.Id -in $importantEventIDs.FailedLogon -and $eventCategories.SecurityEvents.FailedLogons.Count -lt $defaultLimits.FailedLogons) {
                        $eventCategories.SecurityEvents.FailedLogons += $eventObj
                    }
                    if ($event.Id -in $importantEventIDs.AccountLockout -and $eventCategories.SecurityEvents.AccountLockouts.Count -lt $defaultLimits.AccountLockouts) {
                        $eventCategories.SecurityEvents.AccountLockouts += $eventObj
                    }
                    if ($event.Id -in $importantEventIDs.Restart -and $eventCategories.SystemEvents.Restarts.Count -lt $defaultLimits.Restarts) {
                        $eventCategories.SystemEvents.Restarts += $eventObj
                    }
                    if ($event.Id -in $importantEventIDs.Updates -and $eventCategories.SystemEvents.Updates.Count -lt $defaultLimits.Updates) {
                        $eventCategories.SystemEvents.Updates += $eventObj
                    }
                    if ($event.Id -in $importantEventIDs.ApplicationCrash -and $eventCategories.SystemEvents.ApplicationCrashes.Count -lt $defaultLimits.ApplicationCrashes) {
                        $eventCategories.SystemEvents.ApplicationCrashes += $eventObj
                    }
                    if ($event.Id -in $importantEventIDs.HardwareErrors -and $eventCategories.SystemEvents.HardwareErrors.Count -lt $defaultLimits.HardwareErrors) {
                        $eventCategories.SystemEvents.HardwareErrors += $eventObj
                    }
                    if ($event.Id -in ($importantEventIDs.ServiceStart + $importantEventIDs.ServiceStop) -and $eventCategories.SystemEvents.ServiceEvents.Count -lt $defaultLimits.ServiceEvents) {
                        $eventCategories.SystemEvents.ServiceEvents += $eventObj
                    }
                }
            }
            
        } catch {
            Write-Error "Error processing log '$($log.LogName)': $($_.Exception.Message)" -ErrorAction Continue
            $result.Errors += "Error processing log '$($log.LogName)': $($_.Exception.Message)"
        }
    }
    
    $result.LogSummary = $logSummary
    
    # Generate search results summary
    $eventsByLevel = $allEvents | Group-Object Level | ForEach-Object {
        @{
            Level = $_.Name
            Count = $_.Count
            LevelName = switch ($_.Name) {
                "1" { "Critical" }
                "2" { "Error" }
                "3" { "Warning" }
                "4" { "Information" }
                default { "Unknown" }
            }
        }
    }
    
    $eventsByLog = $allEvents | Group-Object LogName | ForEach-Object {
        @{
            LogName = $_.Name
            Count = $_.Count
        }
    }
    
    $topEventIDs = $allEvents | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
        @{
            EventId = $_.Name
            Count = $_.Count
            Description = ($_.Group | Select-Object -First 1).Message.Substring(0, [Math]::Min(100, ($_.Group | Select-Object -First 1).Message.Length))
        }
    }
    
    $result.SearchResults = @{
        TotalEvents = $allEvents.Count
        EventsByLevel = $eventsByLevel
        EventsByLog = $eventsByLog
        TopEventIDs = $topEventIDs
        EventCategories = if (!$isDeepSearch) { $eventCategories } else { @{} }
    }
    
    # Security Analysis
    if (!$SkipSecurityLog -and ($SecurityAnalysis -or !$isDeepSearch)) {
        $securityEvents = $allEvents | Where-Object { $_.LogName -eq 'Security' }
        
        $result.SecurityAnalysis = @{
            TotalSecurityEvents = $securityEvents.Count
            LogonAnalysis = @{
                SuccessfulLogons = ($securityEvents | Where-Object { $_.Id -in $importantEventIDs.SuccessfulLogon }).Count
                FailedLogons = ($securityEvents | Where-Object { $_.Id -in $importantEventIDs.FailedLogon }).Count
                AccountLockouts = ($securityEvents | Where-Object { $_.Id -in $importantEventIDs.AccountLockout }).Count
            }
            PrivilegeEvents = ($securityEvents | Where-Object { $_.Id -in $importantEventIDs.PrivilegeUse }).Count
        }
    }
    
    # Error Pattern Analysis
    $errorEvents = $allEvents | Where-Object { $_.Level -in @(1, 2) }  # Critical and Error
    $warningEvents = $allEvents | Where-Object { $_.Level -eq 3 }      # Warning
    
    $topErrorIDs = $errorEvents | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
        @{
            EventId = $_.Name
            Count = $_.Count
            Level = ($_.Group | Select-Object -First 1).LevelDisplayName
        }
    }
    
    $topErrorSources = $errorEvents | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
        @{
            Source = $_.Name
            Count = $_.Count
        }
    }
    
    $result.ErrorPatterns = @{
        TotalErrors = $errorEvents.Count
        TotalWarnings = $warningEvents.Count
        TopErrorEventIDs = $topErrorIDs
        TopErrorSources = $topErrorSources
    }
    
    # Generate recommendations
    $recommendations = @()
    
    if ($errorEvents.Count -gt 50) {
        $recommendations += "High number of error events ($($errorEvents.Count)) detected. Consider investigating the top error sources."
    }
    
    $failedLogonCount = if ($result.SecurityAnalysis -and $result.SecurityAnalysis.LogonAnalysis) { 
        $result.SecurityAnalysis.LogonAnalysis.FailedLogons 
    } else { 0 }
    
    if ($failedLogonCount -gt 20) {
        $recommendations += "High number of failed logons ($failedLogonCount) detected. Review security logs for potential brute force attempts."
    }
    
    $lockoutCount = if ($result.SecurityAnalysis -and $result.SecurityAnalysis.LogonAnalysis) { 
        $result.SecurityAnalysis.LogonAnalysis.AccountLockouts 
    } else { 0 }
    
    if ($lockoutCount -gt 0) {
        $recommendations += "Account lockout events detected ($lockoutCount). Review account security policies."
    }
    
    $crashEvents = $allEvents | Where-Object { $_.Id -in $importantEventIDs.ApplicationCrash }
    if ($crashEvents.Count -gt 5) {
        $recommendations += "Multiple application crash events detected ($($crashEvents.Count)). Consider reviewing application stability."
    }
    
    $hardwareEvents = $allEvents | Where-Object { $_.Id -in $importantEventIDs.HardwareErrors }
    if ($hardwareEvents.Count -gt 0) {
        $recommendations += "Hardware error events detected ($($hardwareEvents.Count)). Consider hardware diagnostics."
    }
    
    if ($recommendations.Count -eq 0) {
        if ($allEvents.Count -eq 0) {
            $recommendations += "No events found in the specified time range. System appears quiet for this period."
        } else {
            $recommendations += "No significant issues detected in the analyzed time period."
        }
    }
    
    $result.Recommendations = $recommendations
    
    # Set events based on search mode
    if ($isDeepSearch) {
        # In deep search, include all events found
        $result.Events = $allEvents
    } else {
        # In default mode, include only categorized events to keep output manageable
        $limitedEvents = @()
        $limitedEvents += $eventCategories.Critical
        $limitedEvents += $eventCategories.Errors
        $limitedEvents += $eventCategories.Warnings
        $limitedEvents += $eventCategories.SecurityEvents.FailedLogons
        $limitedEvents += $eventCategories.SecurityEvents.AccountLockouts
        $limitedEvents += $eventCategories.SystemEvents.Restarts
        $limitedEvents += $eventCategories.SystemEvents.ApplicationCrashes
        $limitedEvents += $eventCategories.SystemEvents.HardwareErrors
        $limitedEvents += $eventCategories.SystemEvents.Updates
        
        # Only sort if we have events to sort
        if ($limitedEvents.Count -gt 0) {
            try {
                $result.Events = $limitedEvents | Sort-Object TimeCreated -Descending -ErrorAction SilentlyContinue
            } catch {
                Write-Error "Error sorting events: $($_.Exception.Message)" -ErrorAction Continue
                $result.Events = $limitedEvents
            }
        } else {
            $result.Events = @()
        }
    }
    
    # Calculate final statistics
    $endProcessingTime = Get-Date
    $result.Statistics.SearchDuration = ($endProcessingTime - $result.Statistics.StartTime).TotalSeconds
    $result.Statistics.StartTime = $result.Statistics.StartTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    
} catch {
    $result.Errors += "Critical error during execution: $($_.Exception.Message)"
    Write-Error "Critical error: $($_.Exception.Message)" -ErrorAction Continue
}

# Export options
if ($ExportJson -and ![string]::IsNullOrEmpty($OutputPath)) {
    try {
        if (!(Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        $jsonPath = Join-Path $OutputPath "eventlog-analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Error "Results exported to: $jsonPath" -ErrorAction Continue
    } catch {
        $result.Errors += "Failed to export JSON: $($_.Exception.Message)"
    }
}

if ($ExportCsv -and ![string]::IsNullOrEmpty($OutputPath)) {
    try {
        if (!(Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        $csvPath = Join-Path $OutputPath "eventlog-events-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        $result.Events | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Error "Events exported to: $csvPath" -ErrorAction Continue
    } catch {
        $result.Errors += "Failed to export CSV: $($_.Exception.Message)"
    }
}

# Output final JSON result to stdout
$result | ConvertTo-Json -Depth 10 -Compress