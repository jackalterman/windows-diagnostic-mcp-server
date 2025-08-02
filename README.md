# Windows Diagnostics MCP Server

A Model Context Protocol (MCP) server that provides comprehensive Windows system diagnostic capabilities to AI agents. This server allows agents to access Windows event logs, crash information, system uptime, stability analysis, and Windows registry diagnostics.

## Features

### System Diagnostics
- **System Diagnostics**: Comprehensive analysis of Windows events, crashes, and system health
- **BSOD Detection**: Identifies Blue Screen of Death events and critical system errors
- **Shutdown Analysis**: Tracks expected and unexpected system shutdowns
- **Application Crash Monitoring**: Monitors application crashes and failures
- **System Stability Scoring**: Provides stability analysis with actionable recommendations
- **Uptime Tracking**: Reports system uptime and boot information

### Registry Diagnostics
- **Registry Search**: Search the Windows registry by keyword
- **Startup Program Analysis**: Analyze startup programs for suspicious entries
- **System Component Scanning**: Scan services, drivers, and uninstall entries for issues
- **Orphaned Entry Detection**: Find orphaned registry entries pointing to non-existent files
- **Registry Health Assessment**: Overall registry health evaluation
- **Security Risk Scanning**: Scan for potential security risks in the registry

## Installation

### Prerequisites
- Windows 10/11 or Windows Server
- Node.js 18+ 
- PowerShell 5.1+ (built into Windows)
- Administrator privileges (recommended for full functionality)
- PowerShell execution policy configured to allow script execution

### Setup Steps

1. **Clone or download the files**:
   ```bash
   mkdir windows-diagnostics-mcp
   cd windows-diagnostics-mcp
   ```

2. **Save the TypeScript server code** as `src/index.ts`

3. **Create package.json** with the provided configuration

4. **Create tsconfig.json** with the provided TypeScript configuration

5. **Install dependencies**:
   ```bash
   npm install
   ```

6. **Configure PowerShell execution policy** (if not already set):
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
   
   Or for system-wide access (requires Administrator):
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
   ```

7. **Build the server**:
   ```bash
   npm run build
   ```

## Configuration

### For Claude Desktop

Add this to your Claude Desktop configuration file (`%APPDATA%\Claude\claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "windows-diagnostics": {
      "command": "node",
      "args": ["C:\\path\\to\\your\\windows-diagnostics-mcp\\build\\index.js"],
      "env": {
        "NODE_ENV": "production"
      }
    }
  }
}
```

**Important**: For full functionality, run Claude Desktop as Administrator to ensure proper access to event logs and registry.

### For Other MCP Clients

The server can be started with:
```bash
node build/index.js
```

## Available Tools

The MCP server provides the following tools that agents can use:

### System Diagnostic Tools

#### 1. `get_system_diagnostics`
Comprehensive system diagnostic report including all event types.

**Parameters:**
- `daysBack` (number, default: 7): Days to look back for events
- `detailed` (boolean, default: false): Include detailed event information

#### 2. `get_shutdown_events`
Get shutdown and reboot events only.

**Parameters:**
- `daysBack` (number, default: 7): Days to look back for events

#### 3. `get_bsod_events`
Get Blue Screen of Death (BSOD) events.

**Parameters:**
- `daysBack` (number, default: 7): Days to look back for events

#### 4. `get_system_uptime`
Get current system uptime and boot information.

**Parameters:** None

#### 5. `analyze_system_stability`
Analyze system stability and provide recommendations.

**Parameters:**
- `daysBack` (number, default: 30): Days to analyze for stability assessment

### Registry Diagnostic Tools

#### 6. `search_registry`
Search the Windows registry by keyword.

**Parameters:**
- `searchTerm` (string, required): Keyword to search for in the registry
- `maxResults` (number, default: 50): Maximum number of results to return

#### 7. `analyze_startup_programs`
Analyze startup programs for suspicious entries.

**Parameters:** None

#### 8. `scan_system_components`
Scan system components like services, drivers, and uninstall entries for issues.

**Parameters:** None

#### 9. `find_orphaned_entries`
Find orphaned registry entries pointing to non-existent files.

**Parameters:** None

#### 10. `get_registry_health`
Get an overall registry health assessment.

**Parameters:** None

#### 11. `scan_security_risks`
Scan the registry for potential security risks.

**Parameters:** None

## Usage Examples

Once configured with an MCP-compatible client, agents can use commands like:

### System Diagnostics
- "Check my system for any crashes in the last week"
- "Analyze my Windows system stability"
- "Show me recent BSOD events"
- "What's my current system uptime?"
- "Give me a comprehensive diagnostic report"

### Registry Diagnostics
- "Search the registry for entries related to 'Adobe'"
- "Analyze my startup programs for suspicious entries"
- "Check for orphaned registry entries"
- "Scan my registry for security risks"
- "Give me an overall registry health assessment"
- "Scan system components for issues"

## Security Considerations

- **Administrator Rights**: Run with administrator privileges for complete event log and registry access
- **PowerShell Execution**: The server executes PowerShell scripts to gather system information
- **Registry Access**: Registry operations require appropriate permissions and can potentially impact system stability
- **Local Only**: This server only accesses local system information, no network requests
- **Event Log Access**: Requires appropriate permissions to read Windows Event Logs
- **Execution Policy**: PowerShell execution policy must allow script execution

## Troubleshooting

### Common Issues

1. **PowerShell Execution Policy Error**:
   ```
   cannot be loaded because running scripts is disabled on this system
   ```
   **Solution**: Configure PowerShell execution policy:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

2. **Access Denied Errors**:
   - Run the MCP client (e.g., Claude Desktop) as Administrator
   - Some event logs and registry keys require elevated privileges
   - Check user account permissions

3. **Registry Access Errors**:
   - Ensure proper permissions for registry access
   - Some registry keys require SYSTEM-level access
   - Run as Administrator for full registry access

4. **JSON Parse Errors**:
   - Check that PowerShell is outputting valid JSON
   - Verify no additional output is being written to stdout
   - Check for PowerShell version compatibility

5. **No Events Found**:
   - Normal if system has been stable
   - Try increasing the `daysBack` parameter
   - Check if Event Log service is running

6. **Script Execution Blocked**:
   - Verify PowerShell execution policy settings
   - Check for antivirus software blocking script execution
   - Ensure PowerShell modules are not corrupted

### Debugging

Enable debug logging by setting environment variable:
```bash
set DEBUG=mcp:*
node build/index.js
```

### PowerShell Execution Policy Details

The server requires PowerShell scripts to execute. Common execution policies:

- **Restricted**: No scripts allowed (default on some systems)
- **RemoteSigned**: Local scripts allowed, downloaded scripts must be signed
- **Unrestricted**: All scripts allowed (not recommended)

Check current policy:
```powershell
Get-ExecutionPolicy
```

Recommended setting for this server:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Event Types Monitored

The server monitors these Windows Event Log entries:

### System Events
- **1074**: System shutdown initiated by user/application
- **1076**: System shutdown reason recorded
- **6005**: Event Log service started (boot)
- **6006**: Event Log service stopped (shutdown)
- **6008**: Unexpected shutdown detected
- **6009**: System started
- **6013**: System uptime reported

### Critical Events
- **41**: Kernel-Power critical error (unexpected shutdown)
- **1001**: Windows Error Reporting BSOD
- **1003**: System crash dump created

### Application Events
- **1000**: Application error/crash
- **1001**: Application hang
- **1002**: Application recovery

### Hardware/Driver Events
- **219**: Driver loading issues
- **7026**: Service start failures
- **7000**: Service start failures
- **7009**: Service timeouts
- **7031**: Service crashes

## Registry Areas Analyzed

The registry diagnostic tools examine:

### Startup Locations
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`
- Startup folder entries

### System Components
- Installed services
- Device drivers
- Uninstall entries
- System file associations

### Security-Relevant Keys
- Security policies
- User account settings
- Network configurations
- Browser settings

## Output Format

The server provides structured information including:

- **Event timestamps** in ISO format
- **Event descriptions** in plain English
- **Stability scoring** (0-100 scale)
- **Actionable recommendations**
- **System uptime statistics**
- **Memory dump information**
- **Hardware error summaries**
- **Registry key paths and values**
- **Security risk assessments**
- **File existence validation**

## Development

To modify or extend the server:

1. **Edit source**: Modify `src/index.ts`
2. **Rebuild**: Run `npm run build`
3. **Test**: Use MCP inspector or compatible client
4. **Add tools**: Follow the MCP SDK patterns for new diagnostic functions

### Adding New Diagnostic Features

To add new diagnostic capabilities:

1. Extend the PowerShell script with additional event log queries or registry operations
2. Add new tool definitions in the `ListToolsRequestSchema` handler
3. Implement corresponding handler methods
4. Update the documentation
5. Test with appropriate permissions

### PowerShell Script Guidelines

When adding new PowerShell functionality:

- Use `ConvertTo-Json` for structured output
- Handle errors gracefully with try-catch blocks
- Test with different execution policies
- Validate registry key existence before access
- Use appropriate PowerShell cmdlets for registry operations

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome! Please:

1. Follow TypeScript best practices
2. Test with Windows 10/11
3. Document new features
4. Ensure PowerShell compatibility
5. Test registry operations carefully
6. Include proper error handling

## Changelog

### v2.0.0
- Added comprehensive registry diagnostic tools
- Registry search functionality
- Startup program analysis
- System component scanning
- Orphaned entry detection
- Registry health assessment
- Security risk scanning
- Enhanced PowerShell execution policy documentation

### v1.0.0
- Initial release
- Basic diagnostic capabilities
- MCP integration
- Stability analysis
- PowerShell backend