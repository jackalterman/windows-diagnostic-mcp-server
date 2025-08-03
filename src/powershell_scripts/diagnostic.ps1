
param(
    [int]$DaysBack = 7,
    [switch]$Detailed,
    [switch]$JsonOutput
)

# Function to get event log entries with error handling
function Get-SafeEventLog {
    param($LogName, $StartTime, $EventIds)
    
    try {
        Get-WinEvent -FilterHashtable @{
            LogName = $LogName
            StartTime = $StartTime
            ID = $EventIds
        } -ErrorAction SilentlyContinue | Sort-Object TimeCreated -Descending
    }
    catch {
        return @()
    }
}

$StartDate = (Get-Date).AddDays(-$DaysBack)
$Results = @{
    ShutdownEvents = @()
    BSODEvents = @()
    ApplicationCrashes = @()
    UpdateEvents = @()
    DriverIssues = @()
    HardwareErrors = @()
    SystemInfo = @{}
    MemoryDumps = @()
    Summary = @{}
}

# 1. Check for unexpected shutdowns and reboots
$ShutdownEvents = Get-SafeEventLog -LogName "System" -StartTime $StartDate -EventIds @(1074, 1076, 6005, 6006, 6008, 6009, 6013)

foreach ($Event in $ShutdownEvents) {
    $EventInfo = @{
        Type = "Shutdown/Reboot"
        Time = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        EventID = $Event.Id
        Source = $Event.ProviderName
        Description = ""
        Details = if($Detailed) { $Event.Message } else { $Event.Message.Split("`n")[0] }
    }
    
    switch ($Event.Id) {
        1074 { $EventInfo.Description = "System shutdown initiated" }
        1076 { $EventInfo.Description = "System shutdown reason" }
        6005 { $EventInfo.Description = "Event Log service started (system boot)" }
        6006 { $EventInfo.Description = "Event Log service stopped (system shutdown)" }
        6008 { $EventInfo.Description = "Unexpected shutdown detected" }
        6009 { $EventInfo.Description = "System started" }
        6013 { $EventInfo.Description = "System uptime" }
    }
    
    $Results.ShutdownEvents += $EventInfo
}

# 2. Check for Blue Screen of Death (BSOD) events
$BSODEvents = Get-SafeEventLog -LogName "System" -StartTime $StartDate -EventIds @(41, 1001, 1003)

foreach ($Event in $BSODEvents) {
    $EventInfo = @{
        Type = "BSOD/Critical Error"
        Time = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        EventID = $Event.Id
        Source = $Event.ProviderName
        Description = ""
        Details = if($Detailed) { $Event.Message } else { $Event.Message.Split("`n")[0] }
    }
    
    switch ($Event.Id) {
        41 { $EventInfo.Description = "Kernel-Power critical error (unexpected shutdown)" }
        1001 { $EventInfo.Description = "Windows Error Reporting BSOD" }
        1003 { $EventInfo.Description = "System crash dump" }
    }
    
    $Results.BSODEvents += $EventInfo
}

# 3. Check for application crashes
$AppCrashes = Get-SafeEventLog -LogName "Application" -StartTime $StartDate -EventIds @(1000, 1001, 1002)
$CrashSummary = $AppCrashes | Group-Object -Property {$_.Message.Split()[0]} | Sort-Object Count -Descending | Select-Object -First 10

foreach ($Crash in $CrashSummary) {
    $Results.ApplicationCrashes += @{
        Application = $Crash.Name
        CrashCount = $Crash.Count
        LatestCrash = ($Crash.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
    }
}

# 4. Check Windows Update related reboots
$UpdateEvents = Get-SafeEventLog -LogName "System" -StartTime $StartDate -EventIds @(43, 44, 19, 20, 21, 22)

foreach ($Event in $UpdateEvents) {
    $Results.UpdateEvents += @{
        Time = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        EventID = $Event.Id
        Source = $Event.ProviderName
        Description = "Windows Update related reboot"
    }
}

# 5. Check for driver issues
$DriverEvents = Get-SafeEventLog -LogName "System" -StartTime $StartDate -EventIds @(219, 7026, 7000, 7009, 7031)
$DriverIssues = $DriverEvents | Group-Object -Property ProviderName | Sort-Object Count -Descending | Select-Object -First 5

foreach ($Driver in $DriverIssues) {
    $Results.DriverIssues += @{
        DriverService = $Driver.Name
        IssueCount = $Driver.Count
    }
}

# 6. Check for hardware errors
$HardwareEvents = Get-SafeEventLog -LogName "System" -StartTime $StartDate -EventIds @(6, 11, 51, 98, 104)

foreach ($Event in $HardwareEvents) {
    $Results.HardwareErrors += @{
        Time = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        Source = $Event.ProviderName
        Details = if($Detailed) { $Event.Message } else { $Event.Message.Split("`n")[0] }
    }
}

# 7. System uptime and reboot frequency
$Uptime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
$UptimeDuration = (Get-Date) - $Uptime

$Results.SystemInfo = @{
    CurrentUptimeDays = $UptimeDuration.Days
    CurrentUptimeHours = $UptimeDuration.Hours
    CurrentUptimeMinutes = $UptimeDuration.Minutes
    LastBootTime = $Uptime.ToString("yyyy-MM-dd HH:mm:ss")
    RebootCountInPeriod = $Results.ShutdownEvents.Count
    OSVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    TotalMemoryGB = [math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
}

# 8. Check for memory dumps
$DumpPath = "$env:SystemRoot\MEMORY.DMP"
$MiniDumpPath = "$env:SystemRoot\Minidump\*.dmp"

if (Test-Path $DumpPath) {
    $DumpFile = Get-Item $DumpPath
    $Results.MemoryDumps += @{
        Type = "Full"
        Path = $DumpFile.FullName
        LastWrite = $DumpFile.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        SizeMB = [math]::Round($DumpFile.Length/1MB, 2)
    }
}

$MiniDumps = Get-ChildItem $MiniDumpPath -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 5
foreach ($Dump in $MiniDumps) {
    $Results.MemoryDumps += @{
        Type = "Mini"
        Path = $Dump.FullName
        LastWrite = $Dump.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        SizeKB = [math]::Round($Dump.Length/1KB, 2)
    }
}

# Summary - FIXED the CrashCount calculation
$TotalCrashes = 0
if ($Results.ApplicationCrashes.Count -gt 0) {
    $TotalCrashes = ($Results.ApplicationCrashes | ForEach-Object { $_.CrashCount } | Measure-Object -Sum).Sum
}

$Results.Summary = @{
    TotalEventsAnalyzed = ($Results.ShutdownEvents.Count + $Results.BSODEvents.Count + $Results.UpdateEvents.Count + $Results.HardwareErrors.Count)
    CriticalBSODCount = $Results.BSODEvents.Count
    UnexpectedShutdownCount = ($Results.ShutdownEvents | Where-Object {$_.EventID -eq 6008}).Count
    TotalApplicationCrashes = $TotalCrashes
    AnalysisPeriodDays = $DaysBack
    GeneratedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

# Output as JSON
$Results | ConvertTo-Json -Depth 10
