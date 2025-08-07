param(
    [string]$SearchTerm = "",
    [switch]$Detailed,
    [switch]$JsonOutput,
    [switch]$ScanStartup,
    [switch]$ScanServices,
    [switch]$ScanUninstall,
    [switch]$ScanFileAssoc,
    [switch]$ScanDrivers,
    [switch]$FindOrphaned,
    [switch]$SecurityScan,
    [int]$MaxResults = 100,
    [string[]]$HivesToScan = @("HKLM", "HKCU", "HKU", "HKCC", "HKCR")
)

# Function to safely read registry with error handling
function Get-SafeRegistryValue {
    param($Path, $Name = $null)
    
    try {
        if ($Name) {
            Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        } else {
            Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        }
    }
    catch {
        return $null
    }
}

# Function to safely get registry keys
function Get-SafeRegistryKeys {
    param($Path)
    
    try {
        Get-ChildItem -Path $Path -ErrorAction SilentlyContinue
    }
    catch {
        return @()
    }
}

# Function to search registry recursively
function Search-Registry {
    param($Path, $SearchTerm, $MaxDepth = 3, $CurrentDepth = 0)
    
    $Results = @()
    
    if ($CurrentDepth -ge $MaxDepth) { return $Results }
    
    try {
        # Search in key names
        $Keys = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue
        foreach ($Key in $Keys) {
            if ($Key.PSChildName -like "*$SearchTerm*") {
                $Results += @{
                    Type = "KeyName"
                    Path = $Key.Name
                    Match = $Key.PSChildName
                    Found = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                }
            }
            
            # Recursively search subkeys
            if ($CurrentDepth -lt $MaxDepth - 1) {
                $Results += Search-Registry -Path $Key.PSPath -SearchTerm $SearchTerm -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1)
            }
        }
        
        # Search in value names and data
        $Properties = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        if ($Properties) {
            $Properties.PSObject.Properties | ForEach-Object {
                if ($_.Name -notmatch "^(PS|__)" -and $_.Name -like "*$SearchTerm*") {
                    $Results += @{
                        Type = "ValueName"
                        Path = $Path
                        ValueName = $_.Name
                        ValueData = $_.Value
                        Match = $_.Name
                        Found = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    }
                }
                elseif ($_.Name -notmatch "^(PS|__)" -and $_.Value -like "*$SearchTerm*") {
                    $Results += @{
                        Type = "ValueData"
                        Path = $Path
                        ValueName = $_.Name
                        ValueData = $_.Value
                        Match = $_.Value
                        Found = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    }
                }
            }
        }
    }
    catch {
        # Skip inaccessible keys
    }
    
    return $Results
}

# Initialize results structure
$Results = @{
    SearchResults = @()
    StartupPrograms = @()
    ServiceIssues = @()
    UninstallEntries = @()
    FileAssociations = @()
    DriverIssues = @()
    OrphanedEntries = @()
    SecurityIssues = @()
    BadEntries = @()
    RegistryHealth = @{}
    Summary = @{}
}

if (-not $JsonOutput) { Write-Host "Starting Windows Registry Diagnostics..." -ForegroundColor Green }

# 1. Registry Search
if ($SearchTerm) {
    if (-not $JsonOutput) { Write-Host "Searching for: $SearchTerm" -ForegroundColor Yellow }
    
    $SearchPaths = @(
        "HKLM:\SOFTWARE",
        "HKLM:\SYSTEM",
        "HKCU:\SOFTWARE",
        "HKCR:\"
    )
    
    foreach ($SearchPath in $SearchPaths) {
        if (Test-Path $SearchPath) {
            $SearchResults = Search-Registry -Path $SearchPath -SearchTerm $SearchTerm -MaxDepth 2
            $Results.SearchResults += $SearchResults | Select-Object -First ([math]::Min($MaxResults, $SearchResults.Count))
        }
    }
}

# 2. Startup Programs Analysis
if ($ScanStartup -or !$SearchTerm) {
    if (-not $JsonOutput) { Write-Host "Analyzing startup programs..." -ForegroundColor Yellow }
    
    $StartupPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    
    foreach ($Path in $StartupPaths) {
        $StartupItems = Get-SafeRegistryValue -Path $Path
        if ($StartupItems) {
            $StartupItems.PSObject.Properties | ForEach-Object {
                if ($_.Name -notmatch "^PS") {
                    $FilePath = $_.Value -replace '"', ''
                    $FileExists = Test-Path ($FilePath -split ' ')[0]
                    
                    $Results.StartupPrograms += @{
                        Name = $_.Name
                        Path = $_.Value
                        Location = $Path
                        FileExists = $FileExists
                        Suspicious = ($_.Value -match "(temp|appdata|users)" -and !$FileExists)
                    }
                }
            }
        }
    }
}

# 3. Service Issues
if ($ScanServices -or !$SearchTerm) {
    if (-not $JsonOutput) { Write-Host "Scanning for service issues..." -ForegroundColor Yellow }
    
    $ServicesPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
    $Services = Get-SafeRegistryKeys -Path $ServicesPath
    
    foreach ($Service in $Services) {
        $ServiceProps = Get-SafeRegistryValue -Path $Service.PSPath
        if ($ServiceProps) {
            $ImagePath = $ServiceProps.ImagePath
            if ($ImagePath) {
                $ActualPath = ($ImagePath -replace '"', '' -split ' ')[0]
                if (![string]::IsNullOrWhiteSpace($ActualPath) -and !(Test-Path $ActualPath) -and $ActualPath -notmatch "^%") {
                    $Results.ServiceIssues += @{
                        ServiceName = $Service.PSChildName
                        ImagePath = $ImagePath
                        Issue = "Service executable not found"
                        Severity = "Medium"
                    }
                }
            }
        }
    }
}

# 4. Uninstall Entries
if ($ScanUninstall -or !$SearchTerm) {
    if (-not $JsonOutput) { Write-Host "Checking uninstall entries..." -ForegroundColor Yellow }
    
    $UninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    
    foreach ($Path in $UninstallPaths) {
        $UninstallKeys = Get-SafeRegistryKeys -Path $Path
        foreach ($Key in $UninstallKeys) {
            $Props = Get-SafeRegistryValue -Path $Key.PSPath
            if ($Props) {
                $UninstallString = $Props.UninstallString
                if ($UninstallString) {
                    $UninstallPath = ($UninstallString -replace '"', '' -split ' ')[0]
                    $FileExists = Test-Path $UninstallPath
                    
                    if (!$FileExists) {
                        $Results.UninstallEntries += @{
                            DisplayName = $Props.DisplayName
                            UninstallString = $UninstallString
                            Issue = "Uninstaller not found"
                            RegistryKey = $Key.Name
                        }
                    }
                }
            }
        }
    }
}

# 5. File Association Issues
if ($ScanFileAssoc -or !$SearchTerm) {
    if (-not $JsonOutput) { Write-Host "Scanning file associations..." -ForegroundColor Yellow }
    
    $FileTypes = Get-SafeRegistryKeys -Path "HKCR:\"
    $SampleExtensions = $FileTypes | Where-Object { $_.PSChildName -match "^\." } | Select-Object -First 20
    
    foreach ($Ext in $SampleExtensions) {
        $DefaultValue = Get-SafeRegistryValue -Path $Ext.PSPath -Name "(default)"
        if ($DefaultValue."(default)") {
            $ProgId = $DefaultValue."(default)"
            $ProgIdPath = "HKCR:\$ProgId"
            
            if (Test-Path $ProgIdPath) {
                $Command = Get-SafeRegistryValue -Path "$ProgIdPath\shell\open\command" -Name "(default)"
                if ($Command."(default)") {
                    $ExePath = ($Command."(default)" -replace '"', '' -split ' ')[0]
                    if (![string]::IsNullOrWhiteSpace($ExePath) -and !(Test-Path $ExePath) -and $ExePath -notmatch "^%") {
                        $Results.FileAssociations += @{
                            Extension = $Ext.PSChildName
                            ProgId = $ProgId
                            Command = $Command."(default)"
                            Issue = "Associated program not found"
                        }
                    }
                }
            }
        }
    }
}

# 6. Driver Issues
if ($ScanDrivers -or !$SearchTerm) {
    if (-not $JsonOutput) { Write-Host "Checking driver entries..." -ForegroundColor Yellow }
    
    $DriverPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
    $Drivers = Get-SafeRegistryKeys -Path $DriverPath | Where-Object {
        $Props = Get-SafeRegistryValue -Path $_.PSPath
        $Props.Type -eq 1  # Kernel driver
    }
    
    foreach ($Driver in $Drivers) {
        $DriverProps = Get-SafeRegistryValue -Path $Driver.PSPath
        if ($DriverProps.ImagePath) {
            $DriverFile = $DriverProps.ImagePath
            if ($DriverFile -notmatch "^system32" -and !(Test-Path "$env:SystemRoot\System32\drivers\$DriverFile")) {
                $Results.DriverIssues += @{
                    DriverName = $Driver.PSChildName
                    ImagePath = $DriverFile
                    Issue = "Driver file not found"
                }
            }
        }
    }
}

# 7. Find Orphaned Entries
if ($FindOrphaned -or !$SearchTerm) {
    if (-not $JsonOutput) { Write-Host "Finding orphaned entries..." -ForegroundColor Yellow }
    
    # Check for entries pointing to non-existent paths
    $CommonPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        "HKCU:\SOFTWARE\Classes\Applications"
    )
    
    foreach ($Path in $CommonPaths) {
        if (Test-Path $Path) {
            $Apps = Get-SafeRegistryKeys -Path $Path
            foreach ($App in $Apps) {
                $AppProps = Get-SafeRegistryValue -Path $App.PSPath
                if ($AppProps."(default)") {
                    $AppPath = $AppProps."(default)" -replace '"', ''
                    if (![string]::IsNullOrWhiteSpace($AppPath) -and !(Test-Path $AppPath) -and $AppPath -notmatch "^%") {
                        $Results.OrphanedEntries += @{
                            Type = "App Path"
                            Name = $App.PSChildName
                            Path = $AppPath
                            RegistryLocation = $App.Name
                        }
                    }
                }
            }
        }
    }
}

# 8. Security Issues
if ($SecurityScan -or !$SearchTerm) {
    if (-not $JsonOutput) { Write-Host "Performing security scan..." -ForegroundColor Yellow }
    
    # Check for suspicious startup entries
    $SuspiciousLocations = @("temp", "appdata\local\temp", "users\public", "\programdata")
    
    foreach ($Startup in $Results.StartupPrograms) {
        foreach ($SuspiciousLoc in $SuspiciousLocations) {
            if ($Startup.Path -match $SuspiciousLoc) {
                $Results.SecurityIssues += @{
                    Type = "Suspicious Startup Location"
                    Name = $Startup.Name
                    Path = $Startup.Path
                    Risk = "Medium"
                }
            }
        }
    }
    
    # Check for unusual service configurations
    $CriticalServices = @("Winlogon", "LSASS", "Services", "Csrss")
    foreach ($ServiceName in $CriticalServices) {
        $ServicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        if (Test-Path $ServicePath) {
            $ServiceProps = Get-SafeRegistryValue -Path $ServicePath
            if ($ServiceProps.ImagePath -and $ServiceProps.ImagePath -notmatch "system32") {
                $Results.SecurityIssues += @{
                    Type = "Critical Service Modified"
                    Service = $ServiceName
                    ImagePath = $ServiceProps.ImagePath
                    Risk = "High"
                }
            }
        }
    }
}

# 9. Identify Bad/Corrupted Entries
if (-not $JsonOutput) { Write-Host "Identifying bad registry entries..." -ForegroundColor Yellow }

# Combine all issues found
$AllIssues = @()
$AllIssues += $Results.ServiceIssues | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "Service" -PassThru }
$AllIssues += $Results.UninstallEntries | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "Uninstall" -PassThru }
$AllIssues += $Results.FileAssociations | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "FileAssoc" -PassThru }
$AllIssues += $Results.DriverIssues | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "Driver" -PassThru }
$AllIssues += $Results.OrphanedEntries | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "Orphaned" -PassThru }

$Results.BadEntries = $AllIssues

# 10. Registry Health Assessment
$TotalKeys = 0
$AccessibleKeys = 0

# Sample key count from major hives
$TestPaths = @(
    "HKLM:\SOFTWARE",
    "HKCU:\SOFTWARE", 
    "HKCR:\"
)

foreach ($TestPath in $TestPaths) {
    if (Test-Path $TestPath) {
        try {
            $Keys = Get-ChildItem $TestPath -ErrorAction SilentlyContinue | Measure-Object
            $TotalKeys += $Keys.Count
            $AccessibleKeys += $Keys.Count
        }
        catch {
            $TotalKeys += 100  # Estimate
        }
    }
}

$HealthScore = if ($TotalKeys -gt 0) { [math]::Round(($AccessibleKeys / $TotalKeys) * 100, 2) } else { 0 }
$Rating = "Unknown"
if ($HealthScore -ge 95) {
    $Rating = "Excellent"
} elseif ($HealthScore -ge 85) {
    $Rating = "Good"
} elseif ($HealthScore -ge 70) {
    $Rating = "Fair"
} else {
    $Rating = "Poor"
}

$Recommendations = @()
if ($Results.BadEntries.Count -gt 0) {
    $Recommendations += "Review and address the $($Results.BadEntries.Count) identified bad/orphaned entries."
}
if ($Results.SecurityIssues.Count -gt 0) {
    $Recommendations += "Review and mitigate the $($Results.SecurityIssues.Count) potential security risks."
}
if ($HealthScore -lt 85) {
    $Recommendations += "Consider using a dedicated registry cleaning tool for a deeper analysis."
}
if ($Recommendations.Count -eq 0) {
    $Recommendations += "No immediate recommendations. The registry appears to be in good health."
}

$Results.RegistryHealth = @{
    Score = $HealthScore
    Rating = $Rating
    IssuesFound = $Results.BadEntries.Count
    Recommendations = $Recommendations
}

# Summary
$Results.Summary = @{
    SearchResultsCount = $Results.SearchResults.Count
    StartupProgramsFound = $Results.StartupPrograms.Count
    SuspiciousStartupItems = ($Results.StartupPrograms | Where-Object { $_.Suspicious }).Count
    ServiceIssues = $Results.ServiceIssues.Count
    OrphanedUninstallEntries = $Results.UninstallEntries.Count
    BrokenFileAssociations = $Results.FileAssociations.Count
    DriverIssues = $Results.DriverIssues.Count
    OrphanedEntries = $Results.OrphanedEntries.Count
    SecurityIssues = $Results.SecurityIssues.Count
    TotalBadEntries = $Results.BadEntries.Count
    RegistryHealthScore = $Results.RegistryHealth.HealthScore
    ScanParameters = @{
        SearchTerm = $SearchTerm
        MaxResults = $MaxResults
        DetailedScan = $Detailed
        HivesScanned = $HivesToScan -join ", "
    }
    GeneratedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

if (-not $JsonOutput) { Write-Host "Registry diagnostics complete!" -ForegroundColor Green }
if (-not $JsonOutput) { Write-Host "Found $($Results.BadEntries.Count) potential issues" -ForegroundColor $(if($Results.BadEntries.Count -gt 0) {"Red"} else {"Green"}) }

# Output results
if ($JsonOutput) {
    $Results | ConvertTo-Json -Depth 10
} else {
    $Results
}