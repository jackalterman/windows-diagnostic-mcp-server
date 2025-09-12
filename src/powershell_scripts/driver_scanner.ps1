<#
.SYNOPSIS
    Comprehensive Windows driver scanning and analysis tool

.DESCRIPTION
    Scans and analyzes Windows drivers using WMI, providing detailed information about driver status, 
    signing, security, and health. Supports filtering by various criteria and includes security analysis.

.PARAMETER DriverName
    Filter drivers by name or description (supports wildcards)

.PARAMETER DeviceClass
    Filter by device class (e.g., Display, Network, Storage, USB, etc.)

.PARAMETER Manufacturer
    Filter by manufacturer/vendor name (supports wildcards)

.PARAMETER SignedOnly
    Show only signed drivers

.PARAMETER UnsignedOnly
    Show only unsigned drivers

.PARAMETER EnabledOnly
    Show only enabled drivers

.PARAMETER DisabledOnly
    Show only disabled drivers

.PARAMETER WithErrors
    Show only drivers with error states

.PARAMETER CheckSecurity
    Perform security analysis of drivers

.PARAMETER CheckVersions
    Check for outdated drivers and version information

.PARAMETER CheckHealth
    Analyze driver health and device status

.PARAMETER Detailed
    Include detailed driver information

#>

param(
    [string]$DriverName = "",
    [string]$DeviceClass = "",
    [string]$Manufacturer = "",
    [switch]$SignedOnly,
    [switch]$UnsignedOnly,
    [switch]$EnabledOnly,
    [switch]$DisabledOnly,
    [switch]$WithErrors,
    [switch]$CheckSecurity,
    [switch]$CheckVersions,
    [switch]$CheckHealth,
    [switch]$Detailed
)

$Results = @{
    Drivers = @()
    Summary = @{
        TotalDrivers = 0
        SignedDrivers = 0
        UnsignedDrivers = 0
        EnabledDrivers = 0
        DisabledDrivers = 0
        DriversWithErrors = 0
        OutdatedDrivers = 0
        SecurityIssues = 0
    }
    SecurityAnalysis = @{
        UnsignedDrivers = @()
        SuspiciousDrivers = @()
        VulnerableDrivers = @()
        CertificateIssues = @()
    }
    HealthAnalysis = @{
        ErrorDevices = @()
        MissingDrivers = @()
        OutdatedDrivers = @()
        PerformanceIssues = @()
    }
    Errors = @()
}

function Get-DriverInfo {
    try {
        # Get all PnP signed drivers
        $drivers = Get-WmiObject Win32_PnPSignedDriver -ErrorAction Stop
        
        # Get additional driver information from Win32_SystemDriver
        $systemDrivers = Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue
        
        # Get device information
        $devices = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue
        
        return @{
            PnPDrivers = $drivers
            SystemDrivers = $systemDrivers
            Devices = $devices
        }
    } catch {
        $Results.Errors += "Failed to get driver information: $($_.Exception.Message)"
        return $null
    }
}

function Test-DriverSecurity {
    param($Driver)
    
    $securityIssues = @()
    
    # Check if driver is signed
    if ($Driver.IsSigned -eq $false) {
        $securityIssues += "Unsigned driver"
    }
    
    # Check for suspicious names or paths
    $suspiciousPatterns = @("temp", "tmp", "download", "unknown", "generic", "default")
    foreach ($pattern in $suspiciousPatterns) {
        if ($Driver.DriverName -like "*$pattern*" -or $Driver.DriverPathName -like "*$pattern*") {
            $securityIssues += "Suspicious naming pattern: $pattern"
        }
    }
    
    # Check for drivers in non-standard locations
    $standardPaths = @("C:\Windows\System32\drivers\", "C:\Windows\System32\")
    $isStandardPath = $false
    foreach ($path in $standardPaths) {
        if ($Driver.DriverPathName -like "$path*") {
            $isStandardPath = $true
            break
        }
    }
    if (-not $isStandardPath) {
        $securityIssues += "Non-standard driver location"
    }
    
    return $securityIssues
}

function Test-DriverHealth {
    param($Driver, $Devices)
    
    $healthIssues = @()
    
    # Find associated device
    $device = $Devices | Where-Object { $_.Service -eq $Driver.DriverName }
    
    if ($device) {
        # Check device status
        if ($device.Status -ne "OK") {
            $healthIssues += "Device status: $($device.Status)"
        }
        
        # Check for error codes
        if ($device.ConfigManagerErrorCode -ne 0) {
            $errorMsg = switch ($device.ConfigManagerErrorCode) {
                1 { "Device not configured" }
                2 { "Device drivers not installed" }
                3 { "Device driver load failed" }
                4 { "Device hardware malfunction" }
                5 { "Device driver requested resources conflict" }
                6 { "Device driver cannot find free resources" }
                7 { "Device driver cannot load on this device" }
                8 { "Device driver cannot be verified" }
                9 { "Device failed to start" }
                10 { "Device cannot share resources" }
                11 { "Device cannot work properly" }
                12 { "Device cannot find enough free resources" }
                13 { "Device cannot be verified" }
                14 { "Device cannot work properly until computer restart" }
                15 { "Device failed due to filtering" }
                16 { "Device cannot find enough resources" }
                17 { "Device cannot be verified" }
                18 { "Device was not restarted" }
                19 { "Device cannot work properly" }
                20 { "Device has a problem" }
                21 { "Device was disabled" }
                22 { "Device has a problem" }
                23 { "Device was disabled" }
                24 { "Device is not present" }
                25 { "Device is not working properly" }
                26 { "Device cannot start" }
                27 { "Device failed" }
                28 { "Device cannot find enough resources" }
                29 { "Device is not working properly" }
                30 { "Device cannot start" }
                default { "Unknown error code: $($device.ConfigManagerErrorCode)" }
            }
            $healthIssues += $errorMsg
        }
    }
    
    return $healthIssues
}

function Test-DriverVersion {
    param($Driver)
    
    $versionIssues = @()
    
    # Check if driver version is very old (before 2020)
    if ($Driver.DriverVersion) {
        try {
            [version]$Driver.DriverVersion | Out-Null  # Validate version format
            $cutoffDate = Get-Date "2020-01-01"
            if ($Driver.DriverDate -and $Driver.DriverDate -lt $cutoffDate) {
                $versionIssues += "Driver version is older than 2020"
            }
        } catch {
            # Version parsing failed, might be non-standard format
            $versionIssues += "Non-standard version format: $($Driver.DriverVersion)"
        }
    }
    
    return $versionIssues
}

# Main execution
try {
    $driverData = Get-DriverInfo
    if (-not $driverData) {
        throw "Failed to retrieve driver information"
    }
    
    $drivers = $driverData.PnPDrivers
    $systemDrivers = $driverData.SystemDrivers
    $devices = $driverData.Devices
    
    # Apply filters
    $filteredDrivers = $drivers | Where-Object {
        $driverMatches = $true
        
        # Driver name filter
        if ($DriverName -and $DriverName.Trim() -ne "") {
            $driverMatches = $driverMatches -and ($_.DriverName -like "*$DriverName*" -or $_.Description -like "*$DriverName*")
        }
        
        # Device class filter
        if ($DeviceClass -and $DeviceClass.Trim() -ne "") {
            $driverMatches = $driverMatches -and $_.DeviceClass -like "*$DeviceClass*"
        }
        
        # Manufacturer filter
        if ($Manufacturer -and $Manufacturer.Trim() -ne "") {
            $driverMatches = $driverMatches -and $_.Manufacturer -like "*$Manufacturer*"
        }
        
        # Signed/unsigned filter
        if ($SignedOnly) {
            $driverMatches = $driverMatches -and $_.IsSigned -eq $true
        }
        if ($UnsignedOnly) {
            $driverMatches = $driverMatches -and $_.IsSigned -eq $false
        }
        
        # Enabled/disabled filter
        if ($EnabledOnly) {
            $driverMatches = $driverMatches -and $_.IsEnabled -eq $true
        }
        if ($DisabledOnly) {
            $driverMatches = $driverMatches -and $_.IsEnabled -eq $false
        }
        
        return $driverMatches
    }
    
    # Process each driver
    foreach ($driver in $filteredDrivers) {
        $driverInfo = @{
            DriverName = $driver.DriverName
            Description = $driver.Description
            DeviceClass = $driver.DeviceClass
            Manufacturer = $driver.Manufacturer
            DriverVersion = $driver.DriverVersion
            DriverDate = $driver.DriverDate
            DriverPathName = $driver.DriverPathName
            IsSigned = $driver.IsSigned
            IsEnabled = $driver.IsEnabled
            Signer = $driver.Signer
            DeviceID = $driver.DeviceID
            HardwareID = $driver.HardwareID
            CompatID = $driver.CompatID
            InfName = $driver.InfName
            InfSection = $driver.InfSection
            InfSectionExt = $driver.InfSectionExt
            ProviderName = $driver.ProviderName
            DriverDateLocal = $driver.DriverDateLocal
            DriverVersionLocal = $driver.DriverVersionLocal
        }
        
        # Add detailed information if requested
        if ($Detailed) {
            $driverInfo += @{
                DriverType = $driver.DriverType
                DriverRank = $driver.DriverRank
                DriverProvider = $driver.DriverProvider
                DriverMfgName = $driver.DriverMfgName
                DriverOEMInf = $driver.DriverOEMInf
                DriverOEMInfExt = $driver.DriverOEMInfExt
                DriverInfName = $driver.DriverInfName
                DriverInfSection = $driver.DriverInfSection
                DriverInfSectionExt = $driver.DriverInfSectionExt
                DriverInfFileName = $driver.DriverInfFileName
                DriverInfDir = $driver.DriverInfDir
                DriverInfDate = $driver.DriverInfDate
                DriverInfVersion = $driver.DriverInfVersion
                DriverInfSize = $driver.DriverInfSize
                DriverInfSizeLocal = $driver.DriverInfSizeLocal
                DriverInfDateLocal = $driver.DriverInfDateLocal
                DriverInfVersionLocal = $driver.DriverInfVersionLocal
            }
        }
        
        # Security analysis
        if ($CheckSecurity) {
            $securityIssues = Test-DriverSecurity -Driver $driver
            $driverInfo.SecurityIssues = $securityIssues
            
            if ($securityIssues.Count -gt 0) {
                $Results.SecurityAnalysis.UnsignedDrivers += $driverInfo
                $Results.Summary.SecurityIssues++
            }
        }
        
        # Health analysis
        if ($CheckHealth) {
            $healthIssues = Test-DriverHealth -Driver $driver -Devices $devices
            $driverInfo.HealthIssues = $healthIssues
            
            if ($healthIssues.Count -gt 0) {
                $Results.HealthAnalysis.ErrorDevices += $driverInfo
            }
        }
        
        # Version analysis
        if ($CheckVersions) {
            $versionIssues = Test-DriverVersion -Driver $driver
            $driverInfo.VersionIssues = $versionIssues
            
            if ($versionIssues.Count -gt 0) {
                $Results.HealthAnalysis.OutdatedDrivers += $driverInfo
                $Results.Summary.OutdatedDrivers++
            }
        }
        
        # Apply error filter
        if ($WithErrors) {
            $hasErrors = ($CheckHealth -and $healthIssues.Count -gt 0) -or 
                        ($CheckVersions -and $versionIssues.Count -gt 0) -or
                        ($CheckSecurity -and $securityIssues.Count -gt 0)
            if (-not $hasErrors) {
                continue
            }
        }
        
        $Results.Drivers += $driverInfo
    }
    
    # Update summary statistics
    $Results.Summary.TotalDrivers = $Results.Drivers.Count
    $Results.Summary.SignedDrivers = ($Results.Drivers | Where-Object { $_.IsSigned -eq $true }).Count
    $Results.Summary.UnsignedDrivers = ($Results.Drivers | Where-Object { $_.IsSigned -eq $false }).Count
    $Results.Summary.EnabledDrivers = ($Results.Drivers | Where-Object { $_.IsEnabled -eq $true }).Count
    $Results.Summary.DisabledDrivers = ($Results.Drivers | Where-Object { $_.IsEnabled -eq $false }).Count
    $Results.Summary.DriversWithErrors = ($Results.Drivers | Where-Object { $_.HealthIssues -and $_.HealthIssues.Count -gt 0 }).Count
    
} catch {
    $Results.Errors += $_.Exception.Message
}

# Output results as JSON
$Results | ConvertTo-Json -Depth 10
