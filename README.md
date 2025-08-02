# Windows Diagnostics MCP Server

A Model Context Protocol (MCP) server that provides Windows system diagnostic capabilities to AI agents. This server allows agents to access Windows event logs, crash information, system uptime, and stability analysis.

## Features

- **System Diagnostics**: Comprehensive analysis of Windows events, crashes, and system health
- **BSOD Detection**: Identifies Blue Screen of Death events and critical system errors
- **Shutdown Analysis**: Tracks expected and unexpected system shutdowns
- **Application Crash Monitoring**: Monitors application crashes and failures
- **System Stability Scoring**: Provides stability analysis with actionable recommendations
- **Uptime Tracking**: Reports system uptime and boot information

## Installation

### Prerequisites
- Windows 10/11 or Windows Server
- Node.js 18+ 
- PowerShell 5.1+ (built into Windows)
- Administrator privileges (recommended for full functionality)

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

6. **Build the server**:
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

### For Other MCP Clients

The server can be started with:
```bash
node build/index.js
```

## Available Tools

The MCP server provides the following tools that agents can use:

### 1. `get_system_diagnostics`
Comprehensive system diagnostic report including all event types.

**Parameters:**
- `daysBack` (number, default: 7): Days to look back for events
- `detailed` (boolean, default: false): Include detailed event information

### 2. `get_shutdown_events`
Get shutdown and reboot events only.

**Parameters:**
- `daysBack` (number, default: 7): Days to look back for events

### 3. `get_bsod_events`
Get Blue Screen of Death (BSOD) events.

**Parameters:**
- `daysBack` (number, default: 7): Days to look back for events

### 4. `get_system_uptime`
Get current system uptime and boot information.

**Parameters:** None

### 5. `analyze_system_stability`
Analyze system stability and provide recommendations.

**Parameters:**
- `daysBack` (number, default: 30): Days to analyze for stability assessment

## Usage Examples

Once configured with an MCP-compatible client, agents can use commands like:

- "Check my system for any crashes in the last week"
- "Analyze my Windows system stability"
- "Show me recent BSOD events"
- "What's my current system uptime?"
- "Give me a comprehensive diagnostic report"

## Security Considerations

- **Administrator Rights**: Run with administrator privileges for complete event log access
- **PowerShell Execution**: The server executes PowerShell scripts to gather system information
- **Local Only**: This server only accesses local system information, no network requests
- **Event Log Access**: Requires appropriate permissions to read Windows Event Logs

## Troubleshooting

### Common Issues

1. **PowerShell Execution Error**:
   - Ensure PowerShell execution policy allows script execution
   - Run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

2. **Access Denied Errors**:
   - Run the MCP client (e.g., Claude Desktop) as Administrator
   - Some event logs require elevated privileges

3. **JSON Parse Errors**:
   - Check that PowerShell is outputting valid JSON
   - Verify no additional output is being written to stdout

4. **No Events Found**:
   - Normal if system has been stable
   - Try increasing the `daysBack` parameter
   - Check if Event Log service is running

### Debugging

Enable debug logging by setting environment variable:
```bash
set DEBUG=mcp:*
node build/index.js
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

## Output Format

The server provides structured information including:

- **Event timestamps** in ISO format
- **Event descriptions** in plain English
- **Stability scoring** (0-100 scale)
- **Actionable recommendations**
- **System uptime statistics**
- **Memory dump information**
- **Hardware error summaries**

## Development

To modify or extend the server:

1. **Edit source**: Modify `src/index.ts`
2. **Rebuild**: Run `npm run build`
3. **Test**: Use MCP inspector or compatible client
4. **Add tools**: Follow the MCP SDK patterns for new diagnostic functions

### Adding New Diagnostic Features

To add new diagnostic capabilities:

1. Extend the PowerShell script with additional event log queries
2. Add new tool definitions in the `ListToolsRequestSchema` handler
3. Implement corresponding handler methods
4. Update the documentation

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome! Please:

1. Follow TypeScript best practices
2. Test with Windows 10/11
3. Document new features
4. Ensure PowerShell compatibility

## Changelog

### v1.0.0
- Initial release
- Basic diagnostic capabilities
- MCP integration
- Stability analysis
- PowerShell backend