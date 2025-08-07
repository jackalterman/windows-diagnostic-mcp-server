
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
    [switch]$ExportJson,
    [string]$OutputPath = ".\hardware-report.json",
    [bool]$checkTemperatures = $true,
    [bool]$checkFanSpeeds = $true,
    [bool]$checkSmartStatus = $true,
    [bool]$checkMemoryHealth = $true
)

# Initialize results object
$Results = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ComputerName = $env:COMPUTERNAME
    Temperatures = @{}
    FanSpeeds = @{}
    DriveHealth = @{}
    MemoryHealth = @{}
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
            $Results.Temperatures["CPU_Zone_$($temp.InstanceName)"] = @{
                Celsius = $celsius
                Fahrenheit = [math]::Round(($celsius * 9/5) + 32, 1)
                Status = if ($celsius -gt 80) { "Critical" } elseif ($celsius -gt 70) { "Warning" } else { "Normal" }
            }
        }
    }

    # Alternative CPU temp via OpenHardwareMonitor WMI (if installed)
    $ohmTemp = Get-WmiObject -Namespace "root\OpenHardwareMonitor" -Class "Sensor" -ErrorAction SilentlyContinue | 
               Where-Object { $_.SensorType -eq "Temperature" }
    
    if ($ohmTemp) {
        foreach ($sensor in $ohmTemp) {
            $Results.Temperatures[$sensor.Name] = @{
                Celsius = [math]::Round($sensor.Value, 1)
                Fahrenheit = [math]::Round(($sensor.Value * 9/5) + 32, 1)
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
                $Results.Temperatures["GPU_$($probe.DeviceID)"] = @{
                    Celsius = $celsius
                    Fahrenheit = [math]::Round(($celsius * 9/5) + 32, 1)
                    Status = if ($celsius -gt 85) { "Critical" } elseif ($celsius -gt 75) { "Warning" } else { "Normal" }
                }
            }
        }
    }

    if ($Results.Temperatures.Count -eq 0) {
        $Results.Errors += "Temperature sensors not accessible via standard WMI queries"
    }
} catch {
    $Results.Errors += "Temperature monitoring error: $($_.Exception.Message)"
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
            $Results.FanSpeeds[$fan.DeviceID] = @{
                Name = $fan.Name
                RPM = $fan.DesiredSpeed
                Status = $fan.Status
                StatusInfo = $fan.StatusInfo
            }
        }
    }

    # Alternative via OpenHardwareMonitor
    $ohmFans = Get-WmiObject -Namespace "root\OpenHardwareMonitor" -Class "Sensor" -ErrorAction SilentlyContinue |
               Where-Object { $_.SensorType -eq "Fan" }
    
    if ($ohmFans) {
        foreach ($fan in $ohmFans) {
            $Results.FanSpeeds[$fan.Name] = @{
                Name = $fan.Name
                RPM = [math]::Round($fan.Value, 0)
                Status = if ($fan.Value -gt 0) { "Running" } else { "Stopped" }
            }
        }
    }

    if ($Results.FanSpeeds.Count -eq 0) {
        $Results.Errors += "Fan sensors not accessible"
    }
} catch {
    $Results.Errors += "Fan monitoring error: $($_.Exception.Message)"
}
}
#endregion

#region SMART Drive Data
if ($checkSmartStatus) {
try {
    $drives = Get-WmiObject -Class "Win32_DiskDrive"
    
    foreach ($drive in $drives) {
        $driveInfo = @{
            Model = $drive.Model
            Size = [math]::Round($drive.Size / 1GB, 2)
            Interface = $drive.InterfaceType
            Health = "Unknown"
            Temperature = $null
            PowerOnHours = $null
            ReallocatedSectors = $null
        }

        # Get SMART data
        $smartData = Get-WmiObject -Namespace "root\wmi" -Class "MSStorageDriver_FailurePredictStatus" -ErrorAction SilentlyContinue |
                     Where-Object { $_.InstanceName -like "*$($drive.Index)*" }
        
        if ($smartData) {
            $driveInfo.Health = if ($smartData.PredictFailure) { "Failing" } else { "Good" }
        }

        # Get additional SMART attributes
        $smartAttributes = Get-WmiObject -Namespace "root\wmi" -Class "MSStorageDriver_FailurePredictData" -ErrorAction SilentlyContinue |
                          Where-Object { $_.InstanceName -like "*$($drive.Index)*" }
        
        if ($smartAttributes -and $smartAttributes.VendorSpecific) {
            # Parse SMART attributes (simplified)
            $vendorData = $smartAttributes.VendorSpecific
            # Temperature (attribute ID 194)
            # Power-on hours (attribute ID 9)
            # Reallocated sectors (attribute ID 5)
            # Note: Full SMART parsing would require more complex byte parsing
        }

        # Disk performance counters
        try {
            $perfCounter = Get-Counter "\PhysicalDisk(*)\% Disk Time" -ErrorAction SilentlyContinue |
                          Where-Object { $_.CounterSamples.InstanceName -like "*$($drive.Index)*" }
            if ($perfCounter) {
                $driveInfo.DiskTime = [math]::Round($perfCounter.CounterSamples[0].CookedValue, 2)
            }
        } catch {
            # Ignore performance counter errors
        }

        $Results.DriveHealth["Drive_$($drive.Index)"] = $driveInfo
    }
} catch {
    $Results.Errors += "Drive health monitoring error: $($_.Exception.Message)"
}
}
#endregion

#region Memory Health
if ($checkMemoryHealth) {
try {
    # Physical memory information
    $memory = Get-WmiObject -Class "Win32_PhysicalMemory"
    $memoryArray = Get-WmiObject -Class "Win32_PhysicalMemoryArray"
    
    $totalMemory = ($memory | Measure-Object -Property Capacity -Sum).Sum / 1GB
    $memorySlots = $memory.Count
    $maxMemory = ($memoryArray | Measure-Object -Property MaxCapacity -Sum).Sum / 1KB / 1GB

    $Results.MemoryHealth = @{
        TotalMemoryGB = [math]::Round($totalMemory, 2)
        MaxCapacityGB = [math]::Round($maxMemory, 2)
        UsedSlots = $memorySlots
        MaxSlots = $memoryArray.MemoryDevices
        Modules = @()
        Errors = @()
    }

    # Individual memory module details
    foreach ($module in $memory) {
        $moduleInfo = @{
            Location = $module.DeviceLocator
            Capacity = [math]::Round($module.Capacity / 1GB, 2)
            Speed = $module.Speed
            Manufacturer = $module.Manufacturer
            PartNumber = $module.PartNumber
            Status = $module.Status
        }
        $Results.MemoryHealth.Modules += $moduleInfo
    }

    # Memory errors from event log
    $memoryErrors = Get-WinEvent -FilterHashtable @{LogName='System'; ID=41,1001; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
                   Where-Object { $_.LevelDisplayName -eq "Critical" -and $_.Message -like "*memory*" }
    
    if ($memoryErrors) {
        $Results.MemoryHealth.Errors = $memoryErrors | ForEach-Object {
            @{
                Time = $_.TimeCreated
                Level = $_.LevelDisplayName
                Message = $_.Message
            }
        }
    }

    # Current memory usage
    $availableMemory = Get-Counter "\Memory\Available MBytes"
    $Results.MemoryHealth.Usage = @{
        UsedPercentage = [math]::Round((($totalMemory * 1024 - $availableMemory.CounterSamples[0].CookedValue) / ($totalMemory * 1024)) * 100, 1)
        UsedGB = [math]::Round($totalMemory - ($availableMemory.CounterSamples[0].CookedValue/1024), 1)
        TotalGB = [math]::Round($totalMemory, 1)
    }

} catch {
    $Results.Errors += "Memory monitoring error: $($_.Exception.Message)"
}
}
#endregion

#region Final Output
# Export to JSON if requested
if ($ExportJson) {
    try {
        $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
        $Results['ExportPath'] = $OutputPath
    } catch {
        $Results.Errors += "Failed to export report: $($_.Exception.Message)"
    }
}

# Always return the results object as JSON to stdout for the Node.js server
try {
    # Convert to the format expected by TypeScript
    $Output = @{
        Temperatures = @()
        FanSpeeds = @()
        SMARTStatus = @()
        MemoryHealth = @{
            Status = "Unknown"
            Errors = @()
        }
        Errors = $Results.Errors
    }
    
    # Convert temperatures from object to array
    foreach ($key in $Results.Temperatures.Keys) {
        $temp = $Results.Temperatures[$key]
        $Output.Temperatures += @{
            Sensor = $key
            TemperatureC = $temp.Celsius
        }
    }
    
    # Convert fan speeds from object to array
    foreach ($key in $Results.FanSpeeds.Keys) {
        $fan = $Results.FanSpeeds[$key]
        $Output.FanSpeeds += @{
            Fan = $key
            SpeedRPM = $fan.RPM
        }
    }
    
    # Convert drive health to SMART status format
    foreach ($key in $Results.DriveHealth.Keys) {
        $drive = $Results.DriveHealth[$key]
        $Output.SMARTStatus += @{
            Disk = $drive.Model
            Status = $drive.Health
            Attributes = @{
                Size = $drive.Size
                Interface = $drive.Interface
            }
        }
    }
    
    # Set memory health status
    if ($Results.MemoryHealth.Usage) {
        $Output.MemoryHealth.Status = if ($Results.MemoryHealth.Usage.UsedPercentage -gt 90) { "Critical" } elseif ($Results.MemoryHealth.Usage.UsedPercentage -gt 80) { "Warning" } else { "Normal" }
    }
    
    $Output | ConvertTo-Json -Depth 10
} catch {
    @{ Error = "Failed to convert results to JSON: $($_.Exception.Message)" } | ConvertTo-Json
}
#endregion