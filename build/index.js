#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, } from '@modelcontextprotocol/sdk/types.js';
import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { fileURLToPath } from 'url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DIAGNOSTIC_SCRIPT_PATH = path.resolve(__dirname, 'diagnostic.ps1');
const REGISTRY_SCRIPT_PATH = path.resolve(__dirname, 'windows_registry.ps1');
const DIAGNOSTIC_SCRIPT = fs.readFileSync(DIAGNOSTIC_SCRIPT_PATH, 'utf-8');
const REGISTRY_SCRIPT = fs.readFileSync(REGISTRY_SCRIPT_PATH, 'utf-8');
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
                    {
                        name: 'search_registry',
                        description: 'Search the Windows registry by keyword',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                searchTerm: {
                                    type: 'string',
                                    description: 'Keyword to search for in the registry'
                                },
                                maxResults: {
                                    type: 'number',
                                    description: 'Maximum number of results to return (default: 50)',
                                    default: 50
                                }
                            },
                            required: ['searchTerm']
                        }
                    },
                    {
                        name: 'analyze_startup_programs',
                        description: 'Analyze startup programs for suspicious entries',
                        inputSchema: {
                            type: 'object',
                            properties: {},
                        }
                    },
                    {
                        name: 'scan_system_components',
                        description: 'Scan system components like services, drivers, and uninstall entries for issues',
                        inputSchema: {
                            type: 'object',
                            properties: {},
                        }
                    },
                    {
                        name: 'find_orphaned_entries',
                        description: 'Find orphaned registry entries pointing to non-existent files',
                        inputSchema: {
                            type: 'object',
                            properties: {},
                        }
                    },
                    {
                        name: 'get_registry_health',
                        description: 'Get an overall registry health assessment',
                        inputSchema: {
                            type: 'object',
                            properties: {},
                        }
                    },
                    {
                        name: 'scan_security_risks',
                        description: 'Scan the registry for potential security risks',
                        inputSchema: {
                            type: 'object',
                            properties: {},
                        }
                    }
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
                    case 'search_registry':
                        return await this.searchRegistry(args);
                    case 'analyze_startup_programs':
                        return await this.analyzeStartupPrograms();
                    case 'scan_system_components':
                        return await this.scanSystemComponents();
                    case 'find_orphaned_entries':
                        return await this.findOrphanedEntries();
                    case 'get_registry_health':
                        return await this.getRegistryHealth();
                    case 'scan_security_risks':
                        return await this.scanSecurityRisks();
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
    async runPowerShellScript(script, params = {}) {
        return new Promise((resolve, reject) => {
            const psArgs = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command'];
            let fullScript = script;
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
                        reject(new Error(`Failed to parse JSON output: ${parseError instanceof Error ? parseError.message : String(parseError)}\nOutput: ${stdout}`));
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
                    text: `# Windows System Diagnostics Report\n\n## Summary\n- **Analysis Period**: ${result.Summary.AnalysisPeriodDays} days\n- **Total Events**: ${result.Summary.TotalEventsAnalyzed}\n- **Critical BSOD Events**: ${result.Summary.CriticalBSODCount}\n- **Unexpected Shutdowns**: ${result.Summary.UnexpectedShutdownCount}\n- **Application Crashes**: ${result.Summary.TotalApplicationCrashes}\n- **Generated**: ${result.Summary.GeneratedAt}\n\n## System Information\n- **OS**: ${result.SystemInfo.OSVersion}\n- **Last Boot**: ${result.SystemInfo.LastBootTime}\n- **Current Uptime**: ${result.SystemInfo.CurrentUptimeDays} days, ${result.SystemInfo.CurrentUptimeHours} hours, ${result.SystemInfo.CurrentUptimeMinutes} minutes\n- **Total Memory**: ${result.SystemInfo.TotalMemoryGB} GB\n- **Reboots in Period**: ${result.SystemInfo.RebootCountInPeriod}\n\n## Critical Events\n${result.BSODEvents.length > 0 ? `### BSOD Events (⚠️ Critical)\n${result.BSODEvents.map((e) => `- **${e.Time}**: ${e.Description} (Event ID: ${e.EventID})`).join('\n')}` : '### BSOD Events\n- No BSOD events found ✅'}\n\n${result.ShutdownEvents.filter((e) => e.EventID === 6008).length > 0 ? `### Unexpected Shutdowns (⚠️ Warning)\n${result.ShutdownEvents.filter((e) => e.EventID === 6008).map((e) => `- **${e.Time}**: ${e.Description}`).join('\n')}` : '### Unexpected Shutdowns\n- No unexpected shutdowns found ✅'}\n\n## Application Crashes\n${result.ApplicationCrashes.length > 0 ? result.ApplicationCrashes.map((c) => `- **${c.Application}**: ${c.CrashCount} crashes (Latest: ${c.LatestCrash})`).join('\n') : '- No application crashes found ✅'}\n\n## Hardware & Driver Issues\n${result.HardwareErrors.length > 0 ? `### Hardware Errors\n${result.HardwareErrors.map((e) => `- **${e.Time}**: ${e.Source}`).join('\n')}` : '### Hardware Errors\n- No hardware errors found ✅'}\n\n${result.DriverIssues.length > 0 ? `### Driver Issues\n${result.DriverIssues.map((d) => `- **${d.DriverService}**: ${d.IssueCount} issues`).join('\n')}` : '### Driver Issues\n- No driver issues found ✅'}\n\n## Memory Dumps\n${result.MemoryDumps.length > 0 ? result.MemoryDumps.map((d) => `- **${d.Type} Dump**: ${d.Path} (Last Modified: ${d.LastWrite}, Size: ${d.SizeMB || d.SizeKB} ${d.SizeMB ? 'MB' : 'KB'})`).join('\n') : '- No memory dumps found'}\n\n## Recent System Events\n${result.ShutdownEvents.slice(0, 5).map((e) => `- **${e.Time}**: ${e.Description} (Event ID: ${e.EventID})`).join('\n')}`,
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
                    text: `# Shutdown and Reboot Events (Last ${daysBack} days)\n\n${result.ShutdownEvents.length > 0 ?
                        result.ShutdownEvents.map((e) => `- **${e.Time}**: ${e.Description} (Event ID: ${e.EventID}, Source: ${e.Source})`).join('\n')
                        : 'No shutdown/reboot events found in the specified period.'}\n\n**Total Events**: ${result.ShutdownEvents.length}\n**Unexpected Shutdowns**: ${result.ShutdownEvents.filter((e) => e.EventID === 6008).length}`,
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
                    text: `# Blue Screen of Death (BSOD) Events (Last ${daysBack} days)\n\n${result.BSODEvents.length > 0 ?
                        `⚠️ **CRITICAL**: ${result.BSODEvents.length} BSOD event(s) found!\n\n` + result.BSODEvents.map((e) => `- **${e.Time}**: ${e.Description} (Event ID: ${e.EventID}, Source: ${e.Source})\n  Details: ${e.Details.substring(0, 200)}...`).join('\n\n')
                        : '✅ No BSOD events found in the specified period.'}`,
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
                    text: `# System Uptime Information\n\n- **Current Uptime**: ${result.SystemInfo.CurrentUptimeDays} days, ${result.SystemInfo.CurrentUptimeHours} hours, ${result.SystemInfo.CurrentUptimeMinutes} minutes\n- **Last Boot Time**: ${result.SystemInfo.LastBootTime}\n- **Operating System**: ${result.SystemInfo.OSVersion}\n- **Total Physical Memory**: ${result.SystemInfo.TotalMemoryGB} GB\n\n## Uptime Analysis\n${result.SystemInfo.CurrentUptimeDays > 30 ? '⚠️ System has been running for over 30 days. Consider rebooting to apply updates and clear memory.' :
                        result.SystemInfo.CurrentUptimeDays > 7 ? '✅ System uptime is reasonable.' :
                            '📝 Recent boot detected.'}`,
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
        const recommendations = [];
        const issues = [];
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
                    text: `# System Stability Analysis (Last ${daysBack} days)\n\n## Overall Stability Score: ${stabilityScore}/100 (${stabilityRating})\n\n## Issues Detected\n${issues.length > 0 ? issues.map(issue => `- ${issue}`).join('\n') : '- No major issues detected ✅'}\n\n## Recommendations\n${recommendations.length > 0 ? recommendations.map(rec => `- ${rec}`).join('\n') : '- System appears stable, continue regular maintenance'}\n\n## Key Metrics\n- **BSOD Events**: ${bsodCount}\n- **Unexpected Shutdowns**: ${unexpectedShutdowns}\n- **Application Crashes**: ${totalCrashes}\n- **Hardware Errors**: ${hardwareErrors}\n- **Current Uptime**: ${result.SystemInfo.CurrentUptimeDays} days\n\n## Additional Actions\n- Run DISM health check: \`DISM /Online /Cleanup-Image /RestoreHealth\`\n- Check Windows Update for pending updates\n- Review Event Viewer for additional details\n- Consider hardware diagnostics if issues persist`,
                },
            ],
        };
    }
    async searchRegistry(args) {
        const searchTerm = args.searchTerm ?? '';
        const maxResults = args.maxResults ?? 50;
        const result = await this.runPowerShellScript(REGISTRY_SCRIPT, {
            SearchTerm: searchTerm,
            MaxResults: maxResults,
            JsonOutput: true,
        });
        const searchResultsText = result.SearchResults && result.SearchResults.length > 0
            ? result.SearchResults
                .map(r => `- **Hive**: ${r.Hive}\n  **Key**: ${r.KeyPath}\n  **Value**: ${r.ValueName}\n  **Data**: ${r.ValueData}`)
                .join('\n\n')
            : 'No results found.';
        return {
            content: [
                {
                    type: 'text',
                    text: `# Registry Search Results for "${searchTerm}"\n\n${searchResultsText}`,
                },
            ],
        };
    }
    async analyzeStartupPrograms() {
        const result = await this.runPowerShellScript(REGISTRY_SCRIPT, { ScanStartup: true, JsonOutput: true });
        return {
            content: [
                {
                    type: 'text',
                    text: `# Startup Program Analysis\n\n${result.StartupPrograms && result.StartupPrograms.length > 0 ? result.StartupPrograms.map(p => `- **Name**: ${p.Name}\n  **Command**: ${p.Command}\n  **Location**: ${p.Location}\n  **User**: ${p.User}\n  **Verified**: ${p.Verified}\n  **Suspicious**: ${p.Suspicious}`).join('\n\n') : 'No startup programs found.'}`,
                },
            ],
        };
    }
    async scanSystemComponents() {
        const result = await this.runPowerShellScript(REGISTRY_SCRIPT, { ScanServices: true, ScanUninstall: true, ScanFileAssoc: true, ScanDrivers: true, JsonOutput: true });
        return {
            content: [
                {
                    type: 'text',
                    text: `# System Component Scan\n\n${result.SystemComponents && result.SystemComponents.length > 0 ? result.SystemComponents.map(c => `- **Type**: ${c.Type}\n  **Name**: ${c.Name}\n  **Issue**: ${c.Issue}\n  **Details**: ${c.Details}`).join('\n\n') : 'No issues found with system components.'}`,
                },
            ],
        };
    }
    async findOrphanedEntries() {
        const result = await this.runPowerShellScript(REGISTRY_SCRIPT, { FindOrphaned: true, JsonOutput: true });
        return {
            content: [
                {
                    type: 'text',
                    text: `# Orphaned Registry Entries\n\n${result.OrphanedEntries && result.OrphanedEntries.length > 0 ? result.OrphanedEntries.map(o => `- **Path**: ${o.Path}\n  **Type**: ${o.Type}`).join('\n\n') : 'No orphaned entries found.'}`,
                },
            ],
        };
    }
    async getRegistryHealth() {
        const result = await this.runPowerShellScript(REGISTRY_SCRIPT, { JsonOutput: true });
        return {
            content: [
                {
                    type: 'text',
                    text: `# Registry Health Assessment\n\n- **Score**: ${result.RegistryHealth?.Score}/100\n- **Rating**: ${result.RegistryHealth?.Rating}\n- **Issues Found**: ${result.RegistryHealth?.IssuesFound}\n\n## Recommendations\n${result.RegistryHealth && result.RegistryHealth.Recommendations.length > 0 ? result.RegistryHealth.Recommendations.map(r => `- ${r}`).join('\n') : 'No recommendations.'}`,
                },
            ],
        };
    }
    async scanSecurityRisks() {
        const result = await this.runPowerShellScript(REGISTRY_SCRIPT, { SecurityScan: true, JsonOutput: true });
        return {
            content: [
                {
                    type: 'text',
                    text: `# Security Risk Scan\n\n${result.SecurityFindings && result.SecurityFindings.length > 0 ? result.SecurityFindings.map(f => `- **ID**: ${f.ID}\n  **Severity**: ${f.Severity}\n  **Description**: ${f.Description}\n  **Details**: ${f.Details}\n  **Recommendation**: ${f.Recommendation}`).join('\n\n') : 'No security risks found.'}`,
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