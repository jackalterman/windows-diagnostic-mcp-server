#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, } from '@modelcontextprotocol/sdk/types.js';
import { spawn } from 'child_process';
// PowerShell diagnostic script embedded as a string - FIXED VERSION
const DIAGNOSTIC_SCRIPT = `
param(
    [int]$DaysBack = 7,
    [switch]$Detailed,
    [switch]$JsonOutput
)

# Function to get event log entries with error handling
function Get-SafeEventLog {
    param($LogName, $StartTime, $EventIds)
    
    try {
        Get-WinEvent -FilterHashtable @{
            LogName = $LogName
            StartTime = $StartTime
            ID = $EventIds
        } -ErrorAction SilentlyContinue | Sort-Object TimeCreated -Descending
    }
    catch {
        return @()
    }
}

$StartDate = (Get-Date).AddDays(-$DaysBack)
$Results = @{
    ShutdownEvents = @()
    BSODEvents = @()
    ApplicationCrashes = @()
    UpdateEvents = @()
    DriverIssues = @()
    HardwareErrors = @()
    SystemInfo = @{}
    MemoryDumps = @()
    Summary = @{}
}

# 1. Check for unexpected shutdowns and reboots
$ShutdownEvents = Get-SafeEventLog -LogName "System" -StartTime $StartDate -EventIds @(1074, 1076, 6005, 6006, 6008, 6009, 6013)

foreach ($Event in $ShutdownEvents) {
    $EventInfo = @{
        Type = "Shutdown/Reboot"
        Time = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        EventID = $Event.Id
        Source = $Event.ProviderName
        Description = ""
        Details = if($Detailed) { $Event.Message } else { $Event.Message.Split("\`n")[0] }
    }
    
    switch ($Event.Id) {
        1074 { $EventInfo.Description = "System shutdown initiated" }
        1076 { $EventInfo.Description = "System shutdown reason" }
        6005 { $EventInfo.Description = "Event Log service started (system boot)" }
        6006 { $EventInfo.Description = "Event Log service stopped (system shutdown)" }
        6008 { $EventInfo.Description = "Unexpected shutdown detected" }
        6009 { $EventInfo.Description = "System started" }
        6013 { $EventInfo.Description = "System uptime" }
    }
    
    $Results.ShutdownEvents += $EventInfo
}

# 2. Check for Blue Screen of Death (BSOD) events
$BSODEvents = Get-SafeEventLog -LogName "System" -StartTime $StartDate -EventIds @(41, 1001, 1003)

foreach ($Event in $BSODEvents) {
    $EventInfo = @{
        Type = "BSOD/Critical Error"
        Time = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        EventID = $Event.Id
        Source = $Event.ProviderName
        Description = ""
        Details = if($Detailed) { $Event.Message } else { $Event.Message.Split("\`n")[0] }
    }
    
    switch ($Event.Id) {
        41 { $EventInfo.Description = "Kernel-Power critical error (unexpected shutdown)" }
        1001 { $EventInfo.Description = "Windows Error Reporting BSOD" }
        1003 { $EventInfo.Description = "System crash dump" }
    }
    
    $Results.BSODEvents += $EventInfo
}

# 3. Check for application crashes
$AppCrashes = Get-SafeEventLog -LogName "Application" -StartTime $StartDate -EventIds @(1000, 1001, 1002)
$CrashSummary = $AppCrashes | Group-Object -Property {$_.Message.Split()[0]} | Sort-Object Count -Descending | Select-Object -First 10

foreach ($Crash in $CrashSummary) {
    $Results.ApplicationCrashes += @{
        Application = $Crash.Name
        CrashCount = $Crash.Count
        LatestCrash = ($Crash.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
    }
}

# 4. Check Windows Update related reboots
$UpdateEvents = Get-SafeEventLog -LogName "System" -StartTime $StartDate -EventIds @(43, 44, 19, 20, 21, 22)

foreach ($Event in $UpdateEvents) {
    $Results.UpdateEvents += @{
        Time = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        EventID = $Event.Id
        Source = $Event.ProviderName
        Description = "Windows Update related reboot"
    }
}

# 5. Check for driver issues
$DriverEvents = Get-SafeEventLog -LogName "System" -StartTime $StartDate -EventIds @(219, 7026, 7000, 7009, 7031)
$DriverIssues = $DriverEvents | Group-Object -Property ProviderName | Sort-Object Count -Descending | Select-Object -First 5

foreach ($Driver in $DriverIssues) {
    $Results.DriverIssues += @{
        DriverService = $Driver.Name
        IssueCount = $Driver.Count
    }
}

# 6. Check for hardware errors
$HardwareEvents = Get-SafeEventLog -LogName "System" -StartTime $StartDate -EventIds @(6, 11, 51, 98, 104)

foreach ($Event in $HardwareEvents) {
    $Results.HardwareErrors += @{
        Time = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        Source = $Event.ProviderName
        Details = if($Detailed) { $Event.Message } else { $Event.Message.Split("\`n")[0] }
    }
}

# 7. System uptime and reboot frequency
$Uptime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
$UptimeDuration = (Get-Date) - $Uptime

$Results.SystemInfo = @{
    CurrentUptimeDays = $UptimeDuration.Days
    CurrentUptimeHours = $UptimeDuration.Hours
    CurrentUptimeMinutes = $UptimeDuration.Minutes
    LastBootTime = $Uptime.ToString("yyyy-MM-dd HH:mm:ss")
    RebootCountInPeriod = $Results.ShutdownEvents.Count
    OSVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    TotalMemoryGB = [math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
}

# 8. Check for memory dumps
$DumpPath = "$env:SystemRoot\\MEMORY.DMP"
$MiniDumpPath = "$env:SystemRoot\\Minidump\\*.dmp"

if (Test-Path $DumpPath) {
    $DumpFile = Get-Item $DumpPath
    $Results.MemoryDumps += @{
        Type = "Full"
        Path = $DumpFile.FullName
        LastWrite = $DumpFile.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        SizeMB = [math]::Round($DumpFile.Length/1MB, 2)
    }
}

$MiniDumps = Get-ChildItem $MiniDumpPath -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 5
foreach ($Dump in $MiniDumps) {
    $Results.MemoryDumps += @{
        Type = "Mini"
        Path = $Dump.FullName
        LastWrite = $Dump.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        SizeKB = [math]::Round($Dump.Length/1KB, 2)
    }
}

# Summary - FIXED the CrashCount calculation
$TotalCrashes = 0
if ($Results.ApplicationCrashes.Count -gt 0) {
    $TotalCrashes = ($Results.ApplicationCrashes | ForEach-Object { $_.CrashCount } | Measure-Object -Sum).Sum
}

$Results.Summary = @{
    TotalEventsAnalyzed = ($Results.ShutdownEvents.Count + $Results.BSODEvents.Count + $Results.UpdateEvents.Count + $Results.HardwareErrors.Count)
    CriticalBSODCount = $Results.BSODEvents.Count
    UnexpectedShutdownCount = ($Results.ShutdownEvents | Where-Object {$_.EventID -eq 6008}).Count
    TotalApplicationCrashes = $TotalCrashes
    AnalysisPeriodDays = $DaysBack
    GeneratedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

# Output as JSON
$Results | ConvertTo-Json -Depth 10
`;
class WindowsDiagnosticsServer {
    server;
    constructor() {
        this.server = new Server({
            name: 'windows-diagnostics',
            version: '0.1.0',
        }, {
            capabilities: {
                tools: {},
            },
        });
        this.setupToolHandlers();
        // Error handling
        this.server.onerror = (error) => console.error('[MCP Error]', error);
        process.on('SIGINT', async () => {
            await this.server.close();
            process.exit(0);
        });
    }
    setupToolHandlers() {
        this.server.setRequestHandler(ListToolsRequestSchema, async () => {
            return {
                tools: [
                    {
                        name: 'get_system_diagnostics',
                        description: 'Get comprehensive Windows system diagnostics including crashes, reboots, and system health',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                daysBack: {
                                    type: 'number',
                                    description: 'Number of days back to analyze (default: 7)',
                                    default: 7,
                                },
                                detailed: {
                                    type: 'boolean',
                                    description: 'Include detailed event information',
                                    default: false,
                                },
                            },
                        },
                    },
                    {
                        name: 'get_shutdown_events',
                        description: 'Get only shutdown and reboot events',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                daysBack: {
                                    type: 'number',
                                    description: 'Number of days back to analyze (default: 7)',
                                    default: 7,
                                },
                            },
                        },
                    },
                    {
                        name: 'get_bsod_events',
                        description: 'Get Blue Screen of Death (BSOD) events',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                daysBack: {
                                    type: 'number',
                                    description: 'Number of days back to analyze (default: 7)',
                                    default: 7,
                                },
                            },
                        },
                    },
                    {
                        name: 'get_system_uptime',
                        description: 'Get current system uptime and boot information',
                        inputSchema: {
                            type: 'object',
                            properties: {},
                        },
                    },
                    {
                        name: 'analyze_system_stability',
                        description: 'Analyze system stability and provide recommendations',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                daysBack: {
                                    type: 'number',
                                    description: 'Number of days back to analyze (default: 30)',
                                    default: 30,
                                },
                            },
                        },
                    },
                ],
            };
        });
        this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
            const { name, arguments: args } = request.params;
            try {
                switch (name) {
                    case 'get_system_diagnostics':
                        return await this.getSystemDiagnostics(args);
                    case 'get_shutdown_events':
                        return await this.getShutdownEvents(args);
                    case 'get_bsod_events':
                        return await this.getBSODEvents(args);
                    case 'get_system_uptime':
                        return await this.getSystemUptime();
                    case 'analyze_system_stability':
                        return await this.analyzeSystemStability(args);
                    default:
                        throw new Error(`Unknown tool: ${name}`);
                }
            }
            catch (error) {
                return {
                    content: [
                        {
                            type: 'text',
                            text: `Error executing ${name}: ${error instanceof Error ? error.message : String(error)}`,
                        },
                    ],
                };
            }
        });
    }
    // FIXED: Proper PowerShell parameter passing
    async runPowerShellScript(script, params = {}) {
        return new Promise((resolve, reject) => {
            // Build proper PowerShell parameters
            const psArgs = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command'];
            // Add the script
            let fullScript = script;
            // Add parameters properly
            const paramStrings = [];
            Object.entries(params).forEach(([key, value]) => {
                if (typeof value === 'boolean' && value) {
                    paramStrings.push(`-${key}`);
                }
                else if (typeof value === 'number' || typeof value === 'string') {
                    paramStrings.push(`-${key} ${value}`);
                }
            });
            if (paramStrings.length > 0) {
                fullScript = `& { ${script} } ${paramStrings.join(' ')}`;
            }
            psArgs.push(fullScript);
            const powershell = spawn('powershell.exe', psArgs, {
                stdio: ['pipe', 'pipe', 'pipe'],
                shell: false
            });
            let stdout = '';
            let stderr = '';
            powershell.stdout.on('data', (data) => {
                stdout += data.toString();
            });
            powershell.stderr.on('data', (data) => {
                stderr += data.toString();
            });
            powershell.on('close', (code) => {
                if (code !== 0) {
                    reject(new Error(`PowerShell script failed with code ${code}: ${stderr}`));
                }
                else {
                    try {
                        const result = JSON.parse(stdout);
                        resolve(result);
                    }
                    catch (parseError) {
                        reject(new Error(`Failed to parse JSON output: ${parseError}\nOutput: ${stdout}`));
                    }
                }
            });
            powershell.on('error', (error) => {
                reject(new Error(`Failed to start PowerShell: ${error.message}`));
            });
        });
    }
    async getSystemDiagnostics(args) {
        const daysBack = args?.daysBack || 7;
        const detailed = args?.detailed || false;
        const params = {
            DaysBack: daysBack,
            JsonOutput: true,
            ...(detailed && { Detailed: true })
        };
        const result = await this.runPowerShellScript(DIAGNOSTIC_SCRIPT, params);
        return {
            content: [
                {
                    type: 'text',
                    text: `# Windows System Diagnostics Report

## Summary
- **Analysis Period**: ${result.Summary.AnalysisPeriodDays} days
- **Total Events**: ${result.Summary.TotalEventsAnalyzed}
- **Critical BSOD Events**: ${result.Summary.CriticalBSODCount}
- **Unexpected Shutdowns**: ${result.Summary.UnexpectedShutdownCount}
- **Application Crashes**: ${result.Summary.TotalApplicationCrashes}
- **Generated**: ${result.Summary.GeneratedAt}

## System Information
- **OS**: ${result.SystemInfo.OSVersion}
- **Last Boot**: ${result.SystemInfo.LastBootTime}
- **Current Uptime**: ${result.SystemInfo.CurrentUptimeDays} days, ${result.SystemInfo.CurrentUptimeHours} hours, ${result.SystemInfo.CurrentUptimeMinutes} minutes
- **Total Memory**: ${result.SystemInfo.TotalMemoryGB} GB
- **Reboots in Period**: ${result.SystemInfo.RebootCountInPeriod}

## Critical Events
${result.BSODEvents.length > 0 ? `### BSOD Events (⚠️ Critical)
${result.BSODEvents.map((e) => `- **${e.Time}**: ${e.Description} (Event ID: ${e.EventID})`).join('\n')}` : '### BSOD Events\n- No BSOD events found ✅'}

${result.ShutdownEvents.filter((e) => e.EventID === 6008).length > 0 ? `### Unexpected Shutdowns (⚠️ Warning)
${result.ShutdownEvents.filter((e) => e.EventID === 6008).map((e) => `- **${e.Time}**: ${e.Description}`).join('\n')}` : '### Unexpected Shutdowns\n- No unexpected shutdowns found ✅'}

## Application Crashes
${result.ApplicationCrashes.length > 0 ? result.ApplicationCrashes.map((c) => `- **${c.Application}**: ${c.CrashCount} crashes (Latest: ${c.LatestCrash})`).join('\n') : '- No application crashes found ✅'}

## Hardware & Driver Issues
${result.HardwareErrors.length > 0 ? `### Hardware Errors
${result.HardwareErrors.map((e) => `- **${e.Time}**: ${e.Source}`).join('\n')}` : '### Hardware Errors\n- No hardware errors found ✅'}

${result.DriverIssues.length > 0 ? `### Driver Issues
${result.DriverIssues.map((d) => `- **${d.DriverService}**: ${d.IssueCount} issues`).join('\n')}` : '### Driver Issues\n- No driver issues found ✅'}

## Memory Dumps
${result.MemoryDumps.length > 0 ? result.MemoryDumps.map((d) => `- **${d.Type} Dump**: ${d.Path} (Last Modified: ${d.LastWrite}, Size: ${d.SizeMB || d.SizeKB} ${d.SizeMB ? 'MB' : 'KB'})`).join('\n') : '- No memory dumps found'}

## Recent System Events
${result.ShutdownEvents.slice(0, 5).map((e) => `- **${e.Time}**: ${e.Description} (Event ID: ${e.EventID})`).join('\n')}
`,
                },
            ],
        };
    }
    async getShutdownEvents(args) {
        const daysBack = args?.daysBack || 7;
        const result = await this.runPowerShellScript(DIAGNOSTIC_SCRIPT, { DaysBack: daysBack, JsonOutput: true });
        return {
            content: [
                {
                    type: 'text',
                    text: `# Shutdown and Reboot Events (Last ${daysBack} days)

${result.ShutdownEvents.length > 0 ?
                        result.ShutdownEvents.map((e) => `- **${e.Time}**: ${e.Description} (Event ID: ${e.EventID}, Source: ${e.Source})`).join('\n')
                        : 'No shutdown/reboot events found in the specified period.'}

**Total Events**: ${result.ShutdownEvents.length}
**Unexpected Shutdowns**: ${result.ShutdownEvents.filter((e) => e.EventID === 6008).length}
`,
                },
            ],
        };
    }
    async getBSODEvents(args) {
        const daysBack = args?.daysBack || 7;
        const result = await this.runPowerShellScript(DIAGNOSTIC_SCRIPT, { DaysBack: daysBack, JsonOutput: true });
        return {
            content: [
                {
                    type: 'text',
                    text: `# Blue Screen of Death (BSOD) Events (Last ${daysBack} days)

${result.BSODEvents.length > 0 ?
                        `⚠️ **CRITICAL**: ${result.BSODEvents.length} BSOD event(s) found!

` + result.BSODEvents.map((e) => `- **${e.Time}**: ${e.Description} (Event ID: ${e.EventID}, Source: ${e.Source})
  Details: ${e.Details.substring(0, 200)}...`).join('\n\n')
                        : '✅ No BSOD events found in the specified period.'}
`,
                },
            ],
        };
    }
    async getSystemUptime() {
        const result = await this.runPowerShellScript(DIAGNOSTIC_SCRIPT, { DaysBack: 1, JsonOutput: true });
        return {
            content: [
                {
                    type: 'text',
                    text: `# System Uptime Information

- **Current Uptime**: ${result.SystemInfo.CurrentUptimeDays} days, ${result.SystemInfo.CurrentUptimeHours} hours, ${result.SystemInfo.CurrentUptimeMinutes} minutes
- **Last Boot Time**: ${result.SystemInfo.LastBootTime}
- **Operating System**: ${result.SystemInfo.OSVersion}
- **Total Physical Memory**: ${result.SystemInfo.TotalMemoryGB} GB

## Uptime Analysis
${result.SystemInfo.CurrentUptimeDays > 30 ? '⚠️ System has been running for over 30 days. Consider rebooting to apply updates and clear memory.' :
                        result.SystemInfo.CurrentUptimeDays > 7 ? '✅ System uptime is reasonable.' :
                            '📝 Recent boot detected.'}
`,
                },
            ],
        };
    }
    async analyzeSystemStability(args) {
        const daysBack = args?.daysBack || 30;
        const result = await this.runPowerShellScript(DIAGNOSTIC_SCRIPT, { DaysBack: daysBack, JsonOutput: true });
        const bsodCount = result.BSODEvents.length;
        const unexpectedShutdowns = result.ShutdownEvents.filter((e) => e.EventID === 6008).length;
        const totalCrashes = result.Summary.TotalApplicationCrashes || 0;
        const hardwareErrors = result.HardwareErrors.length;
        let stabilityScore = 100;
        let recommendations = [];
        let issues = [];
        if (bsodCount > 0) {
            stabilityScore -= bsodCount * 20;
            issues.push(`${bsodCount} BSOD event(s)`);
            recommendations.push('Investigate BSOD causes - check Windows Update for driver updates');
        }
        if (unexpectedShutdowns > 0) {
            stabilityScore -= unexpectedShutdowns * 10;
            issues.push(`${unexpectedShutdowns} unexpected shutdown(s)`);
            recommendations.push('Check hardware connections and power supply');
        }
        if (totalCrashes > 10) {
            stabilityScore -= Math.min(totalCrashes, 30);
            issues.push(`${totalCrashes} application crashes`);
            recommendations.push('Run system file checker: sfc /scannow');
        }
        if (hardwareErrors > 0) {
            stabilityScore -= hardwareErrors * 5;
            issues.push(`${hardwareErrors} hardware error(s)`);
            recommendations.push('Check hardware health and run memory diagnostics');
        }
        if (result.SystemInfo.CurrentUptimeDays > 30) {
            stabilityScore -= 5;
            recommendations.push('Reboot system to apply updates and clear memory');
        }
        stabilityScore = Math.max(0, stabilityScore);
        let stabilityRating;
        if (stabilityScore >= 90)
            stabilityRating = 'Excellent ✅';
        else if (stabilityScore >= 75)
            stabilityRating = 'Good 👍';
        else if (stabilityScore >= 50)
            stabilityRating = 'Fair ⚠️';
        else
            stabilityRating = 'Poor ❌';
        return {
            content: [
                {
                    type: 'text',
                    text: `# System Stability Analysis (Last ${daysBack} days)

## Overall Stability Score: ${stabilityScore}/100 (${stabilityRating})

## Issues Detected
${issues.length > 0 ? issues.map(issue => `- ${issue}`).join('\n') : '- No major issues detected ✅'}

## Recommendations
${recommendations.length > 0 ? recommendations.map(rec => `- ${rec}`).join('\n') : '- System appears stable, continue regular maintenance'}

## Key Metrics
- **BSOD Events**: ${bsodCount}
- **Unexpected Shutdowns**: ${unexpectedShutdowns}
- **Application Crashes**: ${totalCrashes}
- **Hardware Errors**: ${hardwareErrors}
- **Current Uptime**: ${result.SystemInfo.CurrentUptimeDays} days

## Additional Actions
- Run DISM health check: \`DISM /Online /Cleanup-Image /RestoreHealth\`
- Check Windows Update for pending updates
- Review Event Viewer for additional details
- Consider hardware diagnostics if issues persist
`,
                },
            ],
        };
    }
    async run() {
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
        console.error('Windows Diagnostics MCP server running on stdio');
    }
}
const server = new WindowsDiagnosticsServer();
server.run().catch(console.error);
//# sourceMappingURL=index.js.map