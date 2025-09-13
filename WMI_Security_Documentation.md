# WMI Query Tool Security Documentation

## Overview

The WMI Query tool (`wmi_query`) provides a secure way for AI agents to query Windows Management Instrumentation (WMI) with comprehensive security controls. This tool is designed with security as the paramount concern, implementing multiple layers of protection to prevent malicious or dangerous operations.

## Security Architecture

### 1. Whitelist-Based Access Control

**Approved WMI Classes Only**: The tool maintains a strict whitelist of approved WMI classes that are safe for read-only operations:

- **System Information**: `Win32_ComputerSystem`, `Win32_OperatingSystem`, `Win32_Processor`, etc.
- **Hardware Information**: `Win32_BIOS`, `Win32_BaseBoard`, `Win32_MemoryDevice`, etc.
- **Network Information**: `Win32_NetworkAdapter`, `Win32_NetworkAdapterConfiguration`, etc.
- **Performance Counters**: `Win32_PerfRawData_*` classes for system monitoring
- **Security Information**: `Win32_UserAccount`, `Win32_Group`, `Win32_SystemAccount`, etc.

**Rejected Classes**: Any WMI class not in the whitelist is automatically rejected with a clear security message.

### 2. Input Validation and Sanitization

**Property Name Validation**: 
- Only alphanumeric characters and underscores allowed
- Rejects properties containing dangerous keywords like "Invoke", "Execute", "Run", "Command", "Script", "Code", "Function", "Method", "Call"

**WHERE Clause Security**:
- Comprehensive blacklist of dangerous patterns and executables
- Prevents injection of commands like `cmd.exe`, `powershell.exe`, `wscript.exe`, etc.
- Blocks registry manipulation tools like `regedit.exe`, `regedt32.exe`
- Prevents system management tools like `gpedit.msc`, `secpol.msc`, `services.msc`

### 3. Resource Protection

**Query Timeout**: 
- Default timeout: 30 seconds
- Maximum timeout: 60 seconds
- Prevents long-running queries that could impact system performance

**Result Limits**:
- Default maximum: 100 results
- Hard limit: 1000 results
- Prevents resource exhaustion from large result sets

**Memory Protection**:
- Results are converted to safe JSON format
- No direct object references returned
- Prevents potential memory leaks or object manipulation

### 4. Execution Environment Security

**Read-Only Operations Only**:
- No WMI methods that could modify system state
- No execution of arbitrary code
- No registry modifications
- No service management operations

**Process Isolation**:
- Queries run in isolated PowerShell jobs
- Timeout enforcement at the job level
- Automatic cleanup of failed or timed-out jobs

**Error Handling**:
- Generic error messages to prevent information leakage
- No exposure of internal system paths or sensitive data
- Security-focused error reporting

## Security Features Summary

| Feature | Implementation | Protection Level |
|---------|----------------|------------------|
| Class Whitelist | 80+ approved classes only | High |
| Input Validation | Regex patterns + keyword filtering | High |
| WHERE Clause Security | 50+ forbidden pattern detection | High |
| Query Timeout | 30-60 second limits | Medium |
| Result Limits | 100-1000 item caps | Medium |
| Read-Only Operations | No modification methods | High |
| Process Isolation | PowerShell job execution | Medium |
| Error Sanitization | Generic error messages | Medium |

## Approved WMI Classes

### System Information
- `Win32_ComputerSystem` - Computer system information
- `Win32_OperatingSystem` - Operating system details
- `Win32_Processor` - CPU information
- `Win32_MemoryDevice` - Memory device details
- `Win32_PhysicalMemory` - Physical memory information

### Hardware Components
- `Win32_BIOS` - BIOS information
- `Win32_BaseBoard` - Motherboard details
- `Win32_SystemEnclosure` - System case information
- `Win32_VideoController` - Graphics card information
- `Win32_SoundDevice` - Audio device information
- `Win32_USBController` - USB controller information

### Storage and Drives
- `Win32_LogicalDisk` - Logical disk information
- `Win32_DiskDrive` - Physical disk drives
- `Win32_CDROMDrive` - Optical drive information

### Network Components
- `Win32_NetworkAdapter` - Network adapter information
- `Win32_NetworkAdapterConfiguration` - Network configuration

### Services and Processes
- `Win32_Service` - Windows services
- `Win32_Process` - Running processes
- `Win32_SystemDriver` - System drivers

### Security and Accounts
- `Win32_UserAccount` - User account information
- `Win32_Group` - Group information
- `Win32_SystemAccount` - System account details

### Performance Monitoring
- `Win32_PerfRawData_PerfOS_Processor` - CPU performance data
- `Win32_PerfRawData_PerfOS_Memory` - Memory performance data
- `Win32_PerfRawData_PerfOS_System` - System performance data
- `Win32_PerfRawData_PerfDisk_PhysicalDisk` - Disk performance data
- `Win32_PerfRawData_PerfNet_NetworkInterface` - Network performance data

## Forbidden Patterns

The tool blocks WHERE clauses containing any of these dangerous patterns:

### Executable Files
- `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`
- `rundll32.exe`, `regsvr32.exe`, `mshta.exe`
- `certutil.exe`, `bitsadmin.exe`, `wmic.exe`

### System Management Tools
- `net.exe`, `net1.exe`, `at.exe`, `schtasks.exe`
- `sc.exe`, `taskkill.exe`, `tasklist.exe`
- `systeminfo.exe`, `whoami.exe`, `quser.exe`

### Registry and Security Tools
- `regedit.exe`, `regedt32.exe`
- `gpedit.msc`, `secpol.msc`, `lusrmgr.msc`
- `auditpol.exe`, `secedit.exe`

### Monitoring and Analysis Tools
- `perfmon.exe`, `resmon.exe`, `taskmgr.exe`
- `msconfig.exe`, `dxdiag.exe`, `msinfo32.exe`
- `eventvwr.msc`, `diskmgmt.msc`

## Usage Examples

### Safe Queries
```json
{
  "className": "Win32_Processor",
  "properties": ["Name", "MaxClockSpeed", "NumberOfCores"],
  "maxResults": 10
}
```

```json
{
  "className": "Win32_Service",
  "whereClause": "State = 'Running'",
  "maxResults": 50
}
```

### Rejected Queries
```json
{
  "className": "Win32_Process",
  "whereClause": "Name = 'cmd.exe' AND CommandLine LIKE '%format%'"
}
```
*Rejected: Contains dangerous executable reference*

```json
{
  "className": "Win32_Registry",
  "properties": ["*"]
}
```
*Rejected: Win32_Registry not in whitelist*

## Security Recommendations

1. **Regular Whitelist Review**: Periodically review and update the approved WMI classes list
2. **Monitor Usage**: Log and monitor WMI query usage for suspicious patterns
3. **Access Control**: Ensure only authorized AI agents can access this tool
4. **Network Security**: Run the MCP server in a secure network environment
5. **Regular Updates**: Keep the tool updated with latest security patches

## Compliance and Auditing

The WMI Query tool is designed to meet enterprise security requirements:

- **Read-Only Operations**: No system modifications possible
- **Audit Trail**: All queries are logged with security status
- **Input Validation**: Comprehensive sanitization of all inputs
- **Resource Protection**: Timeout and result limits prevent abuse
- **Error Handling**: Secure error reporting without information leakage

## Conclusion

The WMI Query tool provides a secure, controlled way for AI agents to gather Windows system information through WMI while maintaining strict security boundaries. The multi-layered security approach ensures that only safe, read-only operations are permitted, protecting the system from potential misuse or malicious activities.
