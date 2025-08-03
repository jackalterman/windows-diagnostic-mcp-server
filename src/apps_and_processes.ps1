param(
    [string]$FilterName,
    [int]$MinCPU = 0,
    [int]$MinMemoryMB = 0,
    [int]$KillPID,
    [string]$KillName,
    [string]$StartPath,
    [switch]$ListInstalledApps,
    [string]$AppName,
    [string]$Publisher,
    [switch]$JsonOutput
)

$Results = @{
    RunningProcesses = @()
    KilledProcesses = @()
    StartedProcess = $null
    InstalledApplications = @()
}

function Get-ProcessSafe {
    try {
        Get-Process | Where-Object {
            (!$FilterName -or $_.ProcessName -like "*$FilterName*") -and
            ($_.CPU -ge $MinCPU) -and
            ($_.PM / 1MB -ge $MinMemoryMB)
        } | Sort-Object CPU -Descending
    } catch {
        return @()
    }
}

# 1. Get running processes
$Processes = Get-ProcessSafe

foreach ($Proc in $Processes) {
    $Owner = try {
        $wmi = Get-CimInstance Win32_Process -Filter "ProcessId = $($Proc.Id)"
        $wmi.GetOwner().User
    } catch { "N/A" }

    $Results.RunningProcesses += @{
        Name = $Proc.ProcessName
        PID = $Proc.Id
        CPU = [math]::Round($Proc.CPU, 2)
        MemoryMB = [math]::Round($Proc.PM / 1MB, 2)
        User = $Owner
    }
}

# 2. Kill process by PID or Name
if ($KillPID) {
    try {
        $Killed = Get-Process -Id $KillPID -ErrorAction Stop
        Stop-Process -Id $KillPID -Force -ErrorAction Stop
        $Results.KilledProcesses += @{ PID = $Killed.Id; Name = $Killed.ProcessName }
    } catch {
        $Results.KilledProcesses += @{ PID = $KillPID; Error = $_.Exception.Message }
    }
}

if ($KillName) {
    try {
        $KilledList = Get-Process -Name $KillName -ErrorAction Stop
        foreach ($K in $KilledList) {
            Stop-Process -Id $K.Id -Force -ErrorAction Stop
            $Results.KilledProcesses += @{ PID = $K.Id; Name = $K.ProcessName }
        }
    } catch {
        $Results.KilledProcesses += @{ Name = $KillName; Error = $_.Exception.Message }
    }
}

# 3. Start a process by path
if ($StartPath) {
    try {
        $proc = Start-Process -FilePath $StartPath -PassThru
        $Results.StartedProcess = @{
            Name = $proc.ProcessName
            PID = $proc.Id
            Path = $StartPath
        }
    } catch {
        $Results.StartedProcess = @{ Path = $StartPath; Error = $_.Exception.Message }
    }
}

# 4. List installed applications
if ($ListInstalledApps) {
    $RegPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $RegPaths) {
        try {
            Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.DisplayName) {
                    if (
                        (!$AppName -or $_.DisplayName -like "*$AppName*") -and
                        (!$Publisher -or $_.Publisher -like "*$Publisher*")
                    ) {
                        $Results.InstalledApplications += @{
                            Name = $_.DisplayName
                            Version = $_.DisplayVersion
                            Publisher = $_.Publisher
                            InstallDate = $_.InstallDate
                        }
                    }
                }
            }
        } catch {}
    }
}

# Final Output
if ($JsonOutput) {
    $Results | ConvertTo-Json -Depth 5
} else {
    if ($Results.RunningProcesses.Count -gt 0) {
        Write-Host "`n=== Running Processes ===" -ForegroundColor Cyan
        $Results.RunningProcesses | Format-Table Name, PID, CPU, MemoryMB, User -AutoSize
    }

    if ($Results.KilledProcesses.Count -gt 0) {
        Write-Host "`n=== Killed Processes ===" -ForegroundColor Yellow
        $Results.KilledProcesses | Format-Table -AutoSize
    }

    if ($Results.StartedProcess) {
        Write-Host "`n=== Started Process ===" -ForegroundColor Green
        $Results.StartedProcess | Format-List
    }

    if ($Results.InstalledApplications.Count -gt 0) {
        Write-Host "`n=== Installed Applications ===" -ForegroundColor Magenta
        $Results.InstalledApplications | Sort-Object Name | Format-Table Name, Version, Publisher, InstallDate -AutoSize
    }
}
