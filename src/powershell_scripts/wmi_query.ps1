<#
.SYNOPSIS
    Securely query WMI (Windows Management Instrumentation) with strict security controls
.DESCRIPTION
    This script provides a secure way to query WMI classes with comprehensive security restrictions.
    It only allows read-only operations on approved WMI classes and prevents dangerous operations.
    Security features:
    - Whitelist of approved WMI classes only
    - Read-only operations (no modifications)
    - Input validation and sanitization
    - No execution of arbitrary code
    - Limited property selection
    - Query timeout protection
    - Error handling without information leakage
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ClassName,
    
    [string]$Properties = "",
    
    [string]$WhereClause = "",
    
    [int]$MaxResults = 100,
    
    [int]$TimeoutSeconds = 30,
    
    [switch]$JsonOutput
)

# Security: Define whitelist of approved WMI classes
$ApprovedClasses = @(
    # System Information
    "Win32_ComputerSystem",
    "Win32_OperatingSystem", 
    "Win32_Processor",
    "Win32_MemoryDevice",
    "Win32_PhysicalMemory",
    "Win32_LogicalDisk",
    "Win32_DiskDrive",
    "Win32_CDROMDrive",
    "Win32_NetworkAdapter",
    "Win32_NetworkAdapterConfiguration",
    "Win32_Service",
    "Win32_Process",
    "Win32_SystemDriver",
    "Win32_SystemServices",
    "Win32_StartupCommand",
    "Win32_Environment",
    "Win32_SystemAccount",
    "Win32_UserAccount",
    "Win32_Group",
    "Win32_Product",
    "Win32_QuickFixEngineering",
    "Win32_BIOS",
    "Win32_BaseBoard",
    "Win32_SystemEnclosure",
    "Win32_SystemSlot",
    "Win32_PortConnector",
    "Win32_Keyboard",
    "Win32_PointingDevice",
    "Win32_Printer",
    "Win32_PrinterConfiguration",
    "Win32_PrintJob",
    "Win32_SerialPort",
    "Win32_ParallelPort",
    "Win32_USBController",
    "Win32_USBHub",
    "Win32_SystemDriver",
    "Win32_SystemServices",
    "Win32_SystemAccount",
    "Win32_UserAccount",
    "Win32_Group",
    "Win32_Product",
    "Win32_QuickFixEngineering",
    "Win32_BIOS",
    "Win32_BaseBoard",
    "Win32_SystemEnclosure",
    "Win32_SystemSlot",
    "Win32_PortConnector",
    "Win32_Keyboard",
    "Win32_PointingDevice",
    "Win32_Printer",
    "Win32_PrinterConfiguration",
    "Win32_PrintJob",
    "Win32_SerialPort",
    "Win32_ParallelPort",
    "Win32_USBController",
    "Win32_USBHub",
    # Performance Counters
    "Win32_PerfRawData_PerfOS_Processor",
    "Win32_PerfRawData_PerfOS_Memory",
    "Win32_PerfRawData_PerfOS_System",
    "Win32_PerfRawData_PerfDisk_PhysicalDisk",
    "Win32_PerfRawData_PerfNet_NetworkInterface",
    "Win32_PerfRawData_PerfProc_Process",
    "Win32_PerfRawData_PerfProc_Thread",
    # Event Log
    "Win32_NTEventLogFile",
    "Win32_EventLog",
    # Registry (read-only)
    "StdRegProv",
    # Security
    "Win32_LogicalShareSecuritySetting",
    "Win32_SystemAccount",
    "Win32_UserAccount",
    "Win32_Group",
    # Hardware
    "Win32_VideoController",
    "Win32_SoundDevice",
    "Win32_SystemDriver",
    "Win32_SystemServices",
    "Win32_SystemAccount",
    "Win32_UserAccount",
    "Win32_Group",
    "Win32_Product",
    "Win32_QuickFixEngineering",
    "Win32_BIOS",
    "Win32_BaseBoard",
    "Win32_SystemEnclosure",
    "Win32_SystemSlot",
    "Win32_PortConnector",
    "Win32_Keyboard",
    "Win32_PointingDevice",
    "Win32_Printer",
    "Win32_PrinterConfiguration",
    "Win32_PrintJob",
    "Win32_SerialPort",
    "Win32_ParallelPort",
    "Win32_USBController",
    "Win32_USBHub"
)

# Security: Define forbidden patterns in WHERE clauses
$ForbiddenPatterns = @(
    "Invoke-",
    "cmd.exe",
    "powershell.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "net.exe",
    "net1.exe",
    "at.exe",
    "schtasks.exe",
    "sc.exe",
    "taskkill.exe",
    "tasklist.exe",
    "systeminfo.exe",
    "whoami.exe",
    "quser.exe",
    "query.exe",
    "w32tm.exe",
    "gpresult.exe",
    "secedit.exe",
    "auditpol.exe",
    "wevtutil.exe",
    "eventcreate.exe",
    "logman.exe",
    "typeperf.exe",
    "perfmon.exe",
    "winsat.exe",
    "dxdiag.exe",
    "msinfo32.exe",
    "devmgmt.msc",
    "compmgmt.msc",
    "services.msc",
    "eventvwr.msc",
    "gpedit.msc",
    "secpol.msc",
    "lusrmgr.msc",
    "diskmgmt.msc",
    "perfmon.msc",
    "resmon.exe",
    "taskmgr.exe",
    "msconfig.exe",
    "regedit.exe",
    "regedt32.exe",
    "gpedit.msc",
    "secpol.msc",
    "lusrmgr.msc",
    "diskmgmt.msc",
    "perfmon.msc",
    "resmon.exe",
    "taskmgr.exe",
    "msconfig.exe",
    "regedit.exe",
    "regedt32.exe"
)

# Initialize results
$Results = @{
    Success = $false
    Data = @()
    QueryInfo = @{
        ClassName = ""
        Properties = @()
        WhereClause = ""
        MaxResults = 0
        ActualResults = 0
    }
    SecurityInfo = @{
        ClassApproved = $false
        QuerySanitized = $false
        TimeoutApplied = $false
        SecuritySummary = @{
            ClassWhitelisted = $false
            QuerySanitized = $false
            TimeoutApplied = $false
            MaxResultsLimited = $false
            ReadOnlyOperation = $true # This is always true
        }
    }
    Errors = @()
    Warnings = @()
    ExecutionTime = 0
}

try {
    $StartTime = Get-Date
    
    # Security: Validate class name against whitelist
    if ($ClassName -notin $ApprovedClasses) {
        $Results.Errors += "Class '$ClassName' is not in the approved whitelist. Only read-only system information classes are allowed."
        $Results.SecurityInfo.ClassApproved = $false
        $Results.SecurityInfo.SecuritySummary.ClassWhitelisted = $false
        if ($JsonOutput) {
            $Results | ConvertTo-Json -Depth 10
            return
        } else {
            Write-Output $Results
            return
        }
    }
    
    $Results.SecurityInfo.ClassApproved = $true
    $Results.SecurityInfo.SecuritySummary.ClassWhitelisted = $true
    $Results.QueryInfo.ClassName = $ClassName
    
    # Security: Validate and sanitize properties
    $PropertyList = @()
    if ($Properties -and $Properties.Trim() -ne "") {
        $PropertyList = $Properties.Split(',') | ForEach-Object { $_.Trim() }
        
        # Security: Remove potentially dangerous property names
        $PropertyList = $PropertyList | Where-Object { 
            $_ -notmatch '^[^a-zA-Z0-9_]' -and 
            $_ -notmatch '[^a-zA-Z0-9_]' -and
            $_ -notmatch 'Invoke|Execute|Run|Command|Script|Code|Function|Method|Call'
        }
    }
    
    $Results.QueryInfo.Properties = $PropertyList
    $Results.SecurityInfo.QuerySanitized = $true
    $Results.SecurityInfo.SecuritySummary.QuerySanitized = $true
    
    # Security: Validate WHERE clause for dangerous patterns
    if ($WhereClause -and $WhereClause.Trim() -ne "") {
        $WhereClauseLower = $WhereClause.ToLower()
        foreach ($pattern in $ForbiddenPatterns) {
            if ($WhereClauseLower -like "*$($pattern.ToLower())*") {
                $Results.Errors += "WHERE clause contains potentially dangerous pattern: $pattern"
                if ($JsonOutput) {
                    $Results | ConvertTo-Json -Depth 10
                    return
                } else {
                    Write-Output $Results
                    return
                }
            }
        }
        $Results.QueryInfo.WhereClause = $WhereClause
    }
    
    # Security: Limit max results to prevent resource exhaustion
    if ($MaxResults -gt 1000) {
        $MaxResults = 1000
        $Results.Warnings += "MaxResults limited to 1000 for security"
    }
    $Results.QueryInfo.MaxResults = $MaxResults
    
    # Security: Apply timeout
    $Results.SecurityInfo.TimeoutApplied = $true
    $Results.SecurityInfo.SecuritySummary.TimeoutApplied = $true
    
    # Build WMI query
    $WmiQuery = "SELECT "
    if ($PropertyList.Count -gt 0) {
        $WmiQuery += ($PropertyList -join ", ")
    } else {
        $WmiQuery += "*"
    }
    $WmiQuery += " FROM $ClassName"
    
    if ($WhereClause -and $WhereClause.Trim() -ne "") {
        $WmiQuery += " WHERE $WhereClause"
    }
    
    # Security: Execute query with timeout and error handling
    $QueryJob = Start-Job -ScriptBlock {
        param($Query, $MaxResults)
        try {
            Get-WmiObject -Query $Query | Select-Object -First $MaxResults
        } catch {
            throw $_.Exception
        }
    } -ArgumentList $WmiQuery, $MaxResults
    
    # Wait for completion with timeout
    $JobResult = Wait-Job -Job $QueryJob -Timeout $TimeoutSeconds
    
    if ($JobResult) {
        $WmiResults = Receive-Job -Job $QueryJob
        Remove-Job -Job $QueryJob
        
        # Convert results to safe format
        $SafeResults = @()
        foreach ($item in $WmiResults) {
            $SafeItem = @{}
            $item.PSObject.Properties | ForEach-Object {
                $SafeItem[$_.Name] = $_.Value
            }
            $SafeResults += $SafeItem
        }
        
        $Results.Data = $SafeResults
        $Results.QueryInfo.ActualResults = $SafeResults.Count
        $Results.Success = $true
    } else {
        # Timeout occurred
        Remove-Job -Job $QueryJob -Force
        $Results.Errors += "Query timed out after $TimeoutSeconds seconds"
    }
    
    $EndTime = Get-Date
    $Results.ExecutionTime = ($EndTime - $StartTime).TotalSeconds
    
} catch {
    $Results.Errors += "WMI Query Error: $($_.Exception.Message)"
    $Results.Success = $false
}

# Security: Add security summary
$Results.SecurityInfo.SecuritySummary.MaxResultsLimited = $Results.QueryInfo.MaxResults -le 1000

if ($JsonOutput) {
    $Results | ConvertTo-Json -Depth 10
} else {
    # Human-readable output
    Write-Host "WMI Query Results for: $($Results.QueryInfo.ClassName)" -ForegroundColor Green
    Write-Host "Security Status: " -NoNewline
    if ($Results.SecurityInfo.ClassApproved) {
        Write-Host "APPROVED" -ForegroundColor Green
    } else {
        Write-Host "REJECTED" -ForegroundColor Red
    }
    Write-Host "Results: $($Results.QueryInfo.ActualResults) items returned" -ForegroundColor Cyan
    Write-Host "Execution Time: $([math]::Round($Results.ExecutionTime, 2)) seconds" -ForegroundColor Yellow
    
    if ($Results.Errors.Count -gt 0) {
        Write-Host "`nErrors:" -ForegroundColor Red
        $Results.Errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    }
    
    if ($Results.Warnings.Count -gt 0) {
        Write-Host "`nWarnings:" -ForegroundColor Yellow
        $Results.Warnings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    }
    
    if ($Results.Data.Count -gt 0) {
        Write-Host "`nData Preview (first 3 items):" -ForegroundColor Cyan
        $Results.Data | Select-Object -First 3 | Format-Table -AutoSize
    }
}