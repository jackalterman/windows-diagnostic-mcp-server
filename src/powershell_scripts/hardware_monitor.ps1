Add-Type -AssemblyName System.Web

<#
.SYNOPSIS
    Comprehensive Hardware Monitoring Script for Windows Systems
.DESCRIPTION
    Monitors CPU/GPU temperatures, fan speeds, SMART drive data, and memory health
.NOTES
    Requires Administrator privileges for full functionality
    Some features may require additional WMI providers or specific hardware support
#>

param(
    [switch]$checkTemperatures,
    [switch]$checkFanSpeeds,
    [switch]$checkSmartStatus,
    [switch]$checkMemoryHealth
)

# Default all switches to true if not provided
$checkTemperatures = if ($PSBoundParameters.ContainsKey("checkTemperatures")) { $checkTemperatures } else { $true }
$checkFanSpeeds = if ($PSBoundParameters.ContainsKey("checkFanSpeeds")) { $checkFanSpeeds } else { $true }
$checkSmartStatus = if ($PSBoundParameters.ContainsKey("checkSmartStatus")) { $checkSmartStatus } else { $true }
$checkMemoryHealth = if ($PSBoundParameters.ContainsKey("checkMemoryHealth")) { $checkMemoryHealth } else { $true }

# Initialize results object with the expected structure
$Output = @{
    Temperatures = @()
    FanSpeeds = @()
    SMARTStatus = @()
    MemoryHealth = @{
        Status = "Unknown"
        Errors = @()
    }
    Errors = @()
}

#region Temperature Monitoring
if ($checkTemperatures) {
    try {
        # CPU Temperature (WMI - may not work on all systems)
        $cpuTemp = Get-WmiObject -Namespace "root\wmi" -Class "MSAcpi_ThermalZoneTemperature" -ErrorAction SilentlyContinue
        if ($cpuTemp) {
            foreach ($temp in $cpuTemp) {
                $celsius = [math]::Round(($temp.CurrentTemperature / 10) - 273.15, 1)
                $Output.Temperatures += @{
                    Sensor = "CPU_Zone_$($temp.InstanceName)"
                    TemperatureC = $celsius
                    Status = if ($celsius -gt 80) { "Critical" } elseif ($celsius -gt 70) { "Warning" } else { "Normal" }
                }
            }
        }

        # Alternative CPU temp via OpenHardwareMonitor WMI (if installed)
        $ohmTemp = Get-WmiObject -Namespace "root\OpenHardwareMonitor" -Class "Sensor" -ErrorAction SilentlyContinue | 
                   Where-Object { $_.SensorType -eq "Temperature" }
        
        if ($ohmTemp) {
            foreach ($sensor in $ohmTemp) {
                $Output.Temperatures += @{
                    Sensor = $sensor.Name
                    TemperatureC = [math]::Round($sensor.Value, 1)
                    Status = if ($sensor.Value -gt 80) { "Critical" } elseif ($sensor.Value -gt 70) { "Warning" } else { "Normal" }
                }
            }
        }

        # GPU Temperature via WMI (NVIDIA/AMD specific)
        $gpuTemp = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_TemperatureProbe" -ErrorAction SilentlyContinue
        if ($gpuTemp) {
            foreach ($probe in $gpuTemp) {
                if ($probe.CurrentReading) {
                    $celsius = [math]::Round(($probe.CurrentReading / 10), 1)
                    $Output.Temperatures += @{
                        Sensor = "GPU_$($probe.DeviceID)"
                        TemperatureC = $celsius
                        Status = if ($celsius -gt 85) { "Critical" } elseif ($celsius -gt 75) { "Warning" } else { "Normal" }
                    }
                }
            }
        }

        if ($Output.Temperatures.Count -eq 0) {
            $Output.Errors += "No temperature sensors accessible via standard WMI queries"
        }
    }
    catch {
        $Output.Errors += "Temperature monitoring error: $($_.Exception.Message)"
    }
}
#endregion

#region Fan Speed Monitoring
if ($checkFanSpeeds) {
    try {
        # Fan speeds via WMI
        $fans = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_Fan" -ErrorAction SilentlyContinue
        if ($fans) {
            foreach ($fan in $fans) {
                $Output.FanSpeeds += @{
                    Fan = $fan.DeviceID
                    SpeedRPM = [int]$fan.DesiredSpeed
                }
            }
        }

        # Alternative via OpenHardwareMonitor
        $ohmFans = Get-WmiObject -Namespace "root\OpenHardwareMonitor" -Class "Sensor" -ErrorAction SilentlyContinue |
                   Where-Object { $_.SensorType -eq "Fan" }
        
        if ($ohmFans) {
            foreach ($fan in $ohmFans) {
                $Output.FanSpeeds += @{
                    Fan = $fan.Name
                    SpeedRPM = [math]::Round($fan.Value, 0)
                }
            }
        }

        if ($Output.FanSpeeds.Count -eq 0) {
            $Output.Errors += "No fan sensors accessible"
        }
    }
    catch {
        $Output.Errors += "Fan monitoring error: $($_.Exception.Message)"
    }
}
#endregion

#region SMART Drive Data
if ($checkSmartStatus) {
    try {
        $drives = Get-WmiObject -Class "Win32_DiskDrive" -ErrorAction SilentlyContinue
        
        if ($drives) {
            foreach ($drive in $drives) {
                $smartInfo = @{
                    Disk = $drive.Model
                    Status = "Unknown"
                    Attributes = @{
                        Size = [math]::Round($drive.Size / 1GB, 2)
                        Interface = $drive.InterfaceType
                    }
                }

                # Get SMART data
                $smartData = Get-WmiObject -Namespace "root\wmi" -Class "MSStorageDriver_FailurePredictStatus" -ErrorAction SilentlyContinue |
                            Where-Object { $_.InstanceName -like "*$($drive.Index)*" }
                
                if ($smartData) {
                    $smartInfo.Status = if ($smartData.PredictFailure) { "Warning" } else { "Healthy" }
                }

                $Output.SMARTStatus += $smartInfo
            }
        }

        if ($Output.SMARTStatus.Count -eq 0) {
            $Output.Errors += "No drives found or SMART data not accessible"
        }
    }
    catch {
        $Output.Errors += "Drive health monitoring error: $($_.Exception.Message)"
    }
}
#endregion

#region Memory Health
if ($checkMemoryHealth) {
    try {
        # Physical memory information
        $memory = Get-WmiObject -Class "Win32_PhysicalMemory" -ErrorAction SilentlyContinue
        if ($memory) {
            $totalMemory = ($memory | Measure-Object -Property Capacity -Sum).Sum / 1GB
            $Output.MemoryHealth.TotalMemoryGB = [math]::Round($totalMemory, 1)
            
            # Get current memory usage using Win32_OperatingSystem
            $os = Get-WmiObject -Class "Win32_OperatingSystem" -ErrorAction SilentlyContinue
            if ($os) {
                $totalPhysicalMemory = $os.TotalVisibleMemorySize * 1024  # Convert KB to bytes
                $freePhysicalMemory = $os.FreePhysicalMemory * 1024       # Convert KB to bytes
                $usedMemory = $totalPhysicalMemory - $freePhysicalMemory
                $usedMemoryPercent = [math]::Round(($usedMemory / $totalPhysicalMemory) * 100, 1)
                $Output.MemoryHealth.UsagePercent = $usedMemoryPercent
                $Output.MemoryHealth.UsedMemoryGB = [math]::Round($usedMemory / 1GB, 1)
                $Output.MemoryHealth.FreeMemoryGB = [math]::Round($freePhysicalMemory / 1GB, 1)
                
                # Set memory health status based on usage
                $Output.MemoryHealth.Status = if ($usedMemoryPercent -gt 90) { "Critical" }
                                            elseif ($usedMemoryPercent -gt 80) { "Warning" }
                                            else { "Normal" }
            }
            
            # Check for memory errors in event log
            $memoryErrors = Get-WinEvent -FilterHashtable @{LogName="System"; ID=41,1001; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
                          Where-Object { $_.LevelDisplayName -eq "Critical" -and $_.Message -like "*memory*" }
            
            if ($memoryErrors) {
                $Output.MemoryHealth.Errors = $memoryErrors | Select-Object -First 5 | ForEach-Object {
                    "$($_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")): $($_.Message)"
                }
            }
        }
        else {
            $Output.MemoryHealth.Status = "Unknown"
            $Output.Errors += "Memory information not accessible"
        }
    }
    catch {
        $Output.MemoryHealth.Status = "Error"
        $Output.Errors += "Memory monitoring error: $($_.Exception.Message)"
    }
}
#endregion

# Convert to JSON and output
Write-Output ($Output | ConvertTo-Json -Depth 10 -Compress)
