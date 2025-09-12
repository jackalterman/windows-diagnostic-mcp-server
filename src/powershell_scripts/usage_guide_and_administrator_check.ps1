param(
    [switch]$JsonOutput,
    [switch]$FixExecutionPolicy,
    [switch]$ShowHelp,
    [switch]$Detailed
)

<#
.SYNOPSIS
Checks system privileges, domain status, PowerShell execution policy, and provides usage guidance.

.DESCRIPTION
This tool provides essential system information for diagnostic operations including:
- Administrator privileges check
- Active Directory/Domain connection status
- PowerShell execution policy status and optional fix
- Usage guide for the diagnostic toolset

.PARAMETER JsonOutput
Returns results as JSON instead of console output.

.PARAMETER FixExecutionPolicy
Attempts to set PowerShell execution policy to RemoteSigned for current user.

.PARAMETER ShowHelp
Displays detailed usage guide for the diagnostic toolset.

.PARAMETER Detailed
Provides additional system information and context.
#>

$Results = @{
    IsAdministrator = $false
    AdminDetails = @{}
    DomainInfo = @{}
    PowerShellInfo = @{}
    SystemInfo = @{}
    UsageGuide = @{}
    Recommendations = @()
    Errors = @()
    Warnings = @()
}

try {
    # Check Administrator Privileges
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $Results.IsAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    $Results.AdminDetails = @{
        CurrentUser = $currentUser.Name
        AuthenticationType = $currentUser.AuthenticationType
        IsSystem = $currentUser.IsSystem
        IsGuest = $currentUser.IsGuest
        IsAnonymous = $currentUser.IsAnonymous
    }

    # Check Domain/AD Status
    try {
        $computerInfo = Get-ComputerInfo -Property "CsDomain", "CsDomainRole", "CsWorkgroup", "CsPartOfDomain"
        $Results.DomainInfo = @{
            ComputerName = $env:COMPUTERNAME
            Domain = $computerInfo.CsDomain
            DomainRole = $computerInfo.CsDomainRole
            Workgroup = $computerInfo.CsWorkgroup
            IsPartOfDomain = $computerInfo.CsPartOfDomain
            IsDomainController = ($computerInfo.CsDomainRole -in @(4, 5))  # 4=Backup DC, 5=Primary DC
        }

        # Try to get more AD info if domain-joined
        if ($computerInfo.CsPartOfDomain) {
            try {
                $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $Results.DomainInfo.DomainName = $domain.Name
                $Results.DomainInfo.Forest = $domain.Forest.Name
                $Results.DomainInfo.DomainControllers = @($domain.DomainControllers | ForEach-Object { $_.Name })
            } catch {
                $Results.Warnings += "Could not retrieve detailed AD information: $($_.Exception.Message)"
            }
        }
    } catch {
        $Results.Errors += "Failed to get domain information: $($_.Exception.Message)"
        $Results.DomainInfo = @{
            ComputerName = $env:COMPUTERNAME
            Error = $_.Exception.Message
        }
    }

    # Check PowerShell Execution Policy
    try {
        $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
        $machinePolicy = Get-ExecutionPolicy -Scope LocalMachine
        $processPolicy = Get-ExecutionPolicy -Scope Process
        
        $Results.PowerShellInfo = @{
            CurrentUserPolicy = $currentPolicy.ToString()
            LocalMachinePolicy = $machinePolicy.ToString()
            ProcessPolicy = $processPolicy.ToString()
            EffectivePolicy = (Get-ExecutionPolicy).ToString()
            PSVersion = $PSVersionTable.PSVersion.ToString()
            PSEdition = $PSVersionTable.PSEdition
            CanRunScripts = ($currentPolicy -notin @('Restricted', 'AllSigned')) -or ($machinePolicy -notin @('Restricted', 'AllSigned'))
        }

        # Fix execution policy if requested
        if ($FixExecutionPolicy -and -not $Results.PowerShellInfo.CanRunScripts) {
            try {
                Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
                $Results.PowerShellInfo.PolicyFixed = $true
                $Results.PowerShellInfo.NewPolicy = "RemoteSigned"
                $Results.Recommendations += "✓ Execution policy set to RemoteSigned for current user"
            } catch {
                $Results.Errors += "Failed to set execution policy: $($_.Exception.Message)"
                $Results.PowerShellInfo.PolicyFixed = $false
            }
        }
    } catch {
        $Results.Errors += "Failed to check PowerShell execution policy: $($_.Exception.Message)"
    }

    # System Information
    if ($Detailed) {
        try {
            $osInfo = Get-ComputerInfo -Property "WindowsProductName", "WindowsVersion", "WindowsBuildLabEx", "TotalPhysicalMemory"
            $Results.SystemInfo = @{
                OS = $osInfo.WindowsProductName
                Version = $osInfo.WindowsVersion
                Build = $osInfo.WindowsBuildLabEx
                TotalRAM_GB = [math]::Round($osInfo.TotalPhysicalMemory / 1GB, 2)
                Architecture = $env:PROCESSOR_ARCHITECTURE
                LogicalProcessors = $env:NUMBER_OF_PROCESSORS
                PowerShellHost = $Host.Name
                PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            }
        } catch {
            $Results.Warnings += "Could not retrieve detailed system information: $($_.Exception.Message)"
        }
    }

    # Usage Guide
    if ($ShowHelp -or $true) {  # Always include basic guide
                $Results.UsageGuide = @{
            QuickStart = @{
                BasicDiagnostic = "Use 'get_system_diagnostics' for a quick overview of system health, crashes, and recent events"
                DeepAnalysis = "Use 'analyze_system_stability' with 30+ days for comprehensive stability analysis"
                HardwareCheck = "Use 'hardware_monitor' to check temperatures, fan speeds, and drive health"
                DriverCheck = "Use 'scan_drivers' to analyze driver status, security, and health"
                EventAnalysis = "Use 'event_viewer' with parameters like -SearchKeyword, -Hours, or -Days for detailed log analysis"
            }
            CommonWorkflows = @{
                TroubleshootCrashes = @(
                    "1. Run get_system_diagnostics to see recent crashes",
                    "2. Use get_bsod_events for Blue Screen details",
                    "3. Check hardware_monitor for temperature issues",
                    "4. Use event_viewer with -CriticalOnly or -ErrorsOnly switches"
                )
                PerformanceAnalysis = @(
                    "1. Run hardware_monitor to check system temps and resources",
                    "2. Use list_processes to identify resource-heavy applications",
                    "3. Check analyze_system_stability for patterns over time",
                    "4. Use event_viewer with -SearchTerms 'performance,slow' to find related events"
                )
                SecurityAudit = @(
                    "1. Run scan_security_risks to check for registry vulnerabilities",
                    "2. Use analyze_startup_programs to check for suspicious autostart entries",
                    "3. Check event_viewer with -SecurityAnalysis switch",
                    "4. Review get_registry_health for system integrity"
                )
                DriverTroubleshooting = @(
                    "1. Run scan_drivers with -checkHealth to find problematic drivers",
                    "2. Use scan_drivers with -checkSecurity to identify unsigned drivers",
                    "3. Check scan_drivers with -checkVersions to find outdated drivers",
                    "4. Use scan_drivers with -deviceClass 'Display' for graphics issues",
                    "5. Use scan_drivers with -withErrors to see only problematic drivers"
                )
            }
            ToolCategories = @{
                SystemHealth = @("get_system_diagnostics", "analyze_system_stability", "get_system_uptime")
                Hardware = @("hardware_monitor", "scan_drivers")
                Events = @("event_viewer", "get_bsod_events", "get_shutdown_events")
                Registry = @("get_registry_health", "scan_security_risks", "find_orphaned_entries", "search_registry")
                Processes = @("list_processes", "kill_process", "start_process", "list_installed_apps")
                Startup = @("analyze_startup_programs", "scan_system_components")
                Drivers = @("scan_drivers")
            }
            PermissionNotes = @{
                RequiredForMost = "Many diagnostic operations require Administrator privileges"
                CanRunWithoutAdmin = @("list_processes", "list_installed_apps", "get_system_uptime", "basic hardware_monitor", "basic scan_drivers")
                AdminRecommended = @("event_viewer", "registry operations", "system diagnostics", "process management", "comprehensive driver analysis")
            }
        }
    }

    # Generate Recommendations
    if (-not $Results.IsAdministrator) {
        $Results.Recommendations += "⚠️  Run as Administrator for full diagnostic capabilities"
    }

    if (-not $Results.PowerShellInfo.CanRunScripts) {
        $Results.Recommendations += "⚠️  PowerShell execution policy is restrictive - use FixExecutionPolicy parameter to resolve"
    }

    if ($Results.DomainInfo.IsPartOfDomain) {
        $Results.Recommendations += "ℹ️  Domain-joined computer detected - some operations may be limited by Group Policy"
    }

    if ($Results.SystemInfo -and $Results.SystemInfo.TotalRAM_GB -lt 8) {
        $Results.Recommendations += "💡 System has less than 8GB RAM - consider memory upgrade for better performance"
    }

    # Success summary
    $Results.Summary = @{
        Administrator = $Results.IsAdministrator
        DomainJoined = $Results.DomainInfo.IsPartOfDomain
        ScriptsEnabled = $Results.PowerShellInfo.CanRunScripts
        ReadyForDiagnostics = $Results.IsAdministrator -and $Results.PowerShellInfo.CanRunScripts
    }

} catch {
    $Results.Errors += "Unexpected error: $($_.Exception.Message)"
}

# Output results
if ($JsonOutput) {
    $Results | ConvertTo-Json -Depth 10
} else {
    Write-Host "=== System Information & Diagnostic Setup ===" -ForegroundColor Cyan
    Write-Host ""
    
    # Administrator Status
    if ($Results.IsAdministrator) {
        Write-Host "✓ Administrator Privileges: " -NoNewline -ForegroundColor Green
        Write-Host "ELEVATED" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Administrator Privileges: " -NoNewline -ForegroundColor Yellow
        Write-Host "LIMITED" -ForegroundColor Yellow
    }
    
    Write-Host "   Current User: $($Results.AdminDetails.CurrentUser)"
    
    # Domain Status
    Write-Host ""
    Write-Host "🌐 Domain Information:" -ForegroundColor Cyan
    if ($Results.DomainInfo.IsPartOfDomain) {
        Write-Host "   Status: Domain-joined to $($Results.DomainInfo.Domain)" -ForegroundColor Green
        Write-Host "   Role: $($Results.DomainInfo.DomainRole)"
        if ($Results.DomainInfo.Forest) {
            Write-Host "   Forest: $($Results.DomainInfo.Forest)"
        }
    } else {
        Write-Host "   Status: Workgroup ($($Results.DomainInfo.Workgroup))" -ForegroundColor Yellow
    }
    
    # PowerShell Status
    Write-Host ""
    Write-Host "🔧 PowerShell Configuration:" -ForegroundColor Cyan
    Write-Host "   Version: $($Results.PowerShellInfo.PSVersion) ($($Results.PowerShellInfo.PSEdition))"
    Write-Host "   Execution Policy: $($Results.PowerShellInfo.EffectivePolicy)"
    if ($Results.PowerShellInfo.CanRunScripts) {
        Write-Host "   Script Execution: " -NoNewline
        Write-Host "ENABLED" -ForegroundColor Green
    } else {
        Write-Host "   Script Execution: " -NoNewline
        Write-Host "RESTRICTED" -ForegroundColor Red
    }
    
    if ($Results.PowerShellInfo.PolicyFixed) {
        Write-Host "   ✓ Execution policy updated to $($Results.PowerShellInfo.NewPolicy)" -ForegroundColor Green
    }
    
    # Recommendations
    if ($Results.Recommendations.Count -gt 0) {
        Write-Host ""
        Write-Host "📋 Recommendations:" -ForegroundColor Cyan
        foreach ($rec in $Results.Recommendations) {
            Write-Host "   $rec"
        }
    }
    
    # Quick Usage Guide
    if ($ShowHelp) {
        Write-Host ""
        Write-Host "=== DIAGNOSTIC TOOLSET USAGE GUIDE ===" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "🚀 Quick Start:" -ForegroundColor Yellow
        Write-Host "   Basic Health Check: " -NoNewline
        Write-Host "get_system_diagnostics" -ForegroundColor White
        Write-Host "   Hardware Monitor: " -NoNewline  
        Write-Host "hardware_monitor" -ForegroundColor White
        Write-Host "   Driver Analysis: " -NoNewline
        Write-Host "scan_drivers -checkHealth -checkSecurity" -ForegroundColor White
        Write-Host "   Event Analysis: " -NoNewline
        Write-Host "event_viewer -SearchKeyword 'error' -Hours 24" -ForegroundColor White
        
        Write-Host ""
        Write-Host "🔍 Common Troubleshooting Workflows:" -ForegroundColor Yellow
        Write-Host "   System Crashes → get_system_diagnostics + get_bsod_events + hardware_monitor"
        Write-Host "   Performance Issues → hardware_monitor + list_processes + analyze_system_stability" 
        Write-Host "   Driver Problems → scan_drivers + hardware_monitor + event_viewer"
        Write-Host "   Security Audit → scan_security_risks + analyze_startup_programs + event_viewer"
        
        Write-Host ""
        Write-Host "📚 Tool Categories:" -ForegroundColor Yellow
        Write-Host "   System Health: get_system_diagnostics, analyze_system_stability"
        Write-Host "   Hardware: hardware_monitor, scan_drivers"
        Write-Host "   Events: event_viewer, get_bsod_events"
        Write-Host "   Registry: get_registry_health, scan_security_risks"
        Write-Host "   Processes: list_processes, list_installed_apps"
        Write-Host "   Drivers: scan_drivers"
    }
    
    # Errors and Warnings
    if ($Results.Errors.Count -gt 0) {
        Write-Host ""
        Write-Host "❌ Errors:" -ForegroundColor Red
        foreach ($errorMsg in $Results.Errors) {
            Write-Host "   $errorMsg" -ForegroundColor Red
        }
    }
    
    if ($Results.Warnings.Count -gt 0) {
        Write-Host ""
        Write-Host "⚠️  Warnings:" -ForegroundColor Yellow
        foreach ($warning in $Results.Warnings) {
            Write-Host "   $warning" -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
    Write-Host "Ready for Diagnostics: " -NoNewline
    if ($Results.Summary.ReadyForDiagnostics) {
        Write-Host "YES" -ForegroundColor Green
    } else {
        Write-Host "PARTIAL" -ForegroundColor Yellow
        Write-Host "  (Some tools may have limited functionality)" -ForegroundColor Gray
    }
}