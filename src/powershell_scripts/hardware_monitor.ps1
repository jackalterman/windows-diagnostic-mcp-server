#Requires -RunAsAdministrator
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
    [switch]$Detailed,
    [switch]$ExportJson,
    [string]$OutputPath = ".\hardware-report.json"
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

Write-Host "🔧 Hardware Monitoring Report - $($Results.Timestamp)" -ForegroundColor Cyan
Write-Host "=" * 60

#region Temperature Monitoring
Write-Host "`n🌡️  Temperature Sensors" -ForegroundColor Yellow

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

    # Display temperature results
    if ($Results.Temperatures.Count -gt 0) {
        foreach ($sensor in $Results.Temperatures.GetEnumerator()) {
            $status = switch ($sensor.Value.Status) {
                "Critical" { "🔴" }
                "Warning" { "🟡" }
                default { "🟢" }
            }
            Write-Host "  $status $($sensor.Key): $($sensor.Value.Celsius)°C ($($sensor.Value.Fahrenheit)°F) - $($sensor.Value.Status)"
        }
    } else {
        Write-Host "  ⚠️  No temperature sensors detected via WMI" -ForegroundColor Yellow
        $Results.Errors += "Temperature sensors not accessible via standard WMI queries"
    }
} catch {
    Write-Host "  ❌ Error reading temperature sensors: $($_.Exception.Message)" -ForegroundColor Red
    $Results.Errors += "Temperature monitoring error: $($_.Exception.Message)"
}
#endregion

#region Fan Speed Monitoring
Write-Host "`n🌪️  Fan Speeds" -ForegroundColor Yellow

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

    # Display fan results
    if ($Results.FanSpeeds.Count -gt 0) {
        foreach ($fan in $Results.FanSpeeds.GetEnumerator()) {
            $statusIcon = if ($fan.Value.RPM -gt 0) { "🟢" } else { "🔴" }
            Write-Host "  $statusIcon $($fan.Value.Name): $($fan.Value.RPM) RPM - $($fan.Value.Status)"
        }
    } else {
        Write-Host "  ⚠️  No fan sensors detected" -ForegroundColor Yellow
        $Results.Errors += "Fan sensors not accessible"
    }
} catch {
    Write-Host "  ❌ Error reading fan speeds: $($_.Exception.Message)" -ForegroundColor Red
    $Results.Errors += "Fan monitoring error: $($_.Exception.Message)"
}
#endregion

#region SMART Drive Data
Write-Host "`n💾 Drive Health (SMART Data)" -ForegroundColor Yellow

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

        # Display drive info
        $healthIcon = switch ($driveInfo.Health) {
            "Failing" { "🔴" }
            "Good" { "🟢" }
            default { "🟡" }
        }
        
        Write-Host "  $healthIcon Drive $($drive.Index): $($driveInfo.Model)"
        Write-Host "    Size: $($driveInfo.Size) GB | Interface: $($driveInfo.Interface) | Health: $($driveInfo.Health)"
        if ($driveInfo.DiskTime) {
            Write-Host "    Disk Usage: $($driveInfo.DiskTime)%"
        }
    }
} catch {
    Write-Host "  ❌ Error reading drive health: $($_.Exception.Message)" -ForegroundColor Red
    $Results.Errors += "Drive health monitoring error: $($_.Exception.Message)"
}
#endregion

#region Memory Health
Write-Host "`n🧠 Memory Health" -ForegroundColor Yellow

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
        
        Write-Host "  🟢 $($moduleInfo.Location): $($moduleInfo.Capacity)GB @ $($moduleInfo.Speed)MHz"
        Write-Host "    Manufacturer: $($moduleInfo.Manufacturer) | Part: $($moduleInfo.PartNumber)"
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
        Write-Host "  ⚠️  $($memoryErrors.Count) memory-related errors found in the last 7 days" -ForegroundColor Yellow
    }

    # Current memory usage
    $availableMemory = Get-Counter "\Memory\Available MBytes"
    $usedMemoryPercent = [math]::Round((($totalMemory * 1024 - $availableMemory.CounterSamples[0].CookedValue) / ($totalMemory * 1024)) * 100, 1)
    
    Write-Host "  📊 Memory Usage: $usedMemoryPercent% ($([math]::Round($totalMemory - ($availableMemory.CounterSamples[0].CookedValue/1024), 1))GB used of $([math]::Round($totalMemory, 1))GB)"

} catch {
    Write-Host "  ❌ Error reading memory information: $($_.Exception.Message)" -ForegroundColor Red
    $Results.Errors += "Memory monitoring error: $($_.Exception.Message)"
}
#endregion

#region Summary and Export
Write-Host "`n📋 Summary" -ForegroundColor Green
Write-Host "  Sensors Detected:"
Write-Host "    🌡️  Temperature sensors: $($Results.Temperatures.Count)"
Write-Host "    🌪️  Fan sensors: $($Results.FanSpeeds.Count)"
Write-Host "    💾 Drives monitored: $($Results.DriveHealth.Count)"
Write-Host "    🧠 Memory modules: $($Results.MemoryHealth.Modules.Count)"

if ($Results.Errors.Count -gt 0) {
    Write-Host "`n⚠️  Errors encountered: $($Results.Errors.Count)" -ForegroundColor Yellow
    if ($Detailed) {
        foreach ($error in $Results.Errors) {
            Write-Host "    • $error" -ForegroundColor Yellow
        }
    }
}

# Export to JSON if requested
if ($ExportJson) {
    try {
        $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "`n📄 Report exported to: $OutputPath" -ForegroundColor Green
    } catch {
        Write-Host "`n❌ Failed to export report: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n✅ Hardware monitoring complete!" -ForegroundColor Green
#endregion