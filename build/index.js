#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, } from '@modelcontextprotocol/sdk/types.js';
import * as diagnostics from './tools/diagnostics.js';
import * as registry from './tools/registry.js';
import * as eventViewer from './tools/event_viewer_analyzer.js';
import * as eventViewerSearch from './tools/event_viewer_search.js';
import * as apps from './tools/apps_and_processes.js';
import * as hardware from './tools/hardware_monitor.js';
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
                    },
                    {
                        name: 'list_processes',
                        description: 'List running processes with optional filters',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                filterName: {
                                    type: 'string',
                                    description: 'Filter processes by name (wildcards accepted)',
                                },
                                minCPU: {
                                    type: 'number',
                                    description: 'Minimum CPU usage to include',
                                },
                                minMemoryMB: {
                                    type: 'number',
                                    description: 'Minimum memory usage in MB to include',
                                },
                            },
                        },
                    },
                    {
                        name: 'kill_process',
                        description: 'Kill a process by its PID or name',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                pid: {
                                    type: 'number',
                                    description: 'Process ID to kill',
                                },
                                name: {
                                    type: 'string',
                                    description: 'Process name to kill (all matching instances)',
                                },
                            },
                        },
                    },
                    {
                        name: 'start_process',
                        description: 'Start a new process from an executable path',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                path: {
                                    type: 'string',
                                    description: 'Full path to the executable to start',
                                },
                            },
                            required: ['path'],
                        },
                    },
                    {
                        name: 'list_installed_apps',
                        description: 'List installed applications with optional filters',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                appName: {
                                    type: 'string',
                                    description: 'Filter by application name (wildcards accepted)',
                                },
                                publisher: {
                                    type: 'string',
                                    description: 'Filter by publisher name (wildcards accepted)',
                                },
                            },
                        },
                    },
                    {
                        name: 'hardware_monitor',
                        description: 'Monitors hardware health including temperatures, fan speeds, drive SMART status, and memory health.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                checkTemperatures: {
                                    type: 'boolean',
                                    description: 'Check CPU and GPU temperatures',
                                    default: true,
                                },
                                checkFanSpeeds: {
                                    type: 'boolean',
                                    description: 'Check system fan speeds',
                                    default: true,
                                },
                                checkSmartStatus: {
                                    type: 'boolean',
                                    description: 'Check storage drive SMART status',
                                    default: true,
                                },
                                checkMemoryHealth: {
                                    type: 'boolean',
                                    description: 'Check memory health',
                                    default: true,
                                },
                            },
                        },
                    },
                    {
                        name: 'event_viewer_analyzer',
                        description: 'Analyze Windows Event Viewer logs with advanced filtering and analysis',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                logNames: {
                                    type: 'array',
                                    items: { type: 'string' },
                                    description: 'Names of the event logs to search (e.g., Application, System)',
                                },
                                searchTerms: {
                                    type: 'array',
                                    items: { type: 'string' },
                                    description: 'Keywords to search for in log messages',
                                },
                                eventIds: {
                                    type: 'array',
                                    items: { type: 'number' },
                                    description: 'Specific event IDs to filter by',
                                },
                                sources: {
                                    type: 'array',
                                    items: { type: 'string' },
                                    description: 'Event sources to filter by',
                                },
                                hours: {
                                    type: 'number',
                                    description: 'Number of hours back to search',
                                },
                                days: {
                                    type: 'number',
                                    description: 'Number of days back to search',
                                },
                                startTime: {
                                    type: 'string',
                                    description: 'Start time for the search (e.g., "YYYY-MM-DDTHH:mm:ss")',
                                },
                                endTime: {
                                    type: 'string',
                                    description: 'End time for the search (e.g., "YYYY-MM-DDTHH:mm:ss")',
                                },
                                errorsOnly: {
                                    type: 'boolean',
                                    description: 'Only show events with level Error',
                                },
                                warningsOnly: {
                                    type: 'boolean',
                                    description: 'Only show events with level Warning',
                                },
                                criticalOnly: {
                                    type: 'boolean',
                                    description: 'Only show events with level Critical',
                                },
                                securityAnalysis: {
                                    type: 'boolean',
                                    description: 'Perform a security-focused analysis of events',
                                },
                                detailed: {
                                    type: 'boolean',
                                    description: 'Include detailed event information',
                                },
                                exportJson: {
                                    type: 'boolean',
                                    description: 'Export results to a JSON file',
                                },
                                exportCsv: {
                                    type: 'boolean',
                                    description: 'Export results to a CSV file',
                                },
                                outputPath: {
                                    type: 'string',
                                    description: 'Path to save the exported file',
                                },
                                maxEvents: {
                                    type: 'number',
                                    description: 'Maximum number of events to return',
                                },
                                showStats: {
                                    type: 'boolean',
                                    description: 'Show statistics about the events found',
                                },
                                groupBySource: {
                                    type: 'boolean',
                                    description: 'Group events by their source',
                                },
                                timelineView: {
                                    type: 'boolean',
                                    description: 'Display events in a timeline view',
                                },
                            },
                        },
                    },
                    {
                        name: 'event_viewer_search',
                        description: 'Comprehensive Windows Event Viewer search tool that enumerates all available logs and searches across them for keywords, event IDs, or other criteria. This tool can discover and search all Windows event logs, not just the main four.',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                searchKeyword: {
                                    type: 'string',
                                    description: 'Keyword to search for in event messages',
                                },
                                eventIds: {
                                    type: 'array',
                                    items: { type: 'number' },
                                    description: 'Specific event IDs to filter by',
                                },
                                sources: {
                                    type: 'array',
                                    items: { type: 'string' },
                                    description: 'Event sources/providers to filter by',
                                },
                                logNames: {
                                    type: 'array',
                                    items: { type: 'string' },
                                    description: 'Specific log names to search (if empty, searches all available logs)',
                                },
                                hours: {
                                    type: 'number',
                                    description: 'Number of hours back to search (default: 24)',
                                },
                                days: {
                                    type: 'number',
                                    description: 'Number of days back to search (overrides hours if specified)',
                                },
                                startTime: {
                                    type: 'string',
                                    description: 'Start time for the search (format: "YYYY-MM-DDTHH:mm:ss")',
                                },
                                endTime: {
                                    type: 'string',
                                    description: 'End time for the search (format: "YYYY-MM-DDTHH:mm:ss")',
                                },
                                maxEventsPerLog: {
                                    type: 'number',
                                    description: 'Maximum number of events to return per log (default: 100)',
                                },
                                includeDisabledLogs: {
                                    type: 'boolean',
                                    description: 'Include disabled logs in the search',
                                },
                                errorsOnly: {
                                    type: 'boolean',
                                    description: 'Only show events with level Error',
                                },
                                warningsOnly: {
                                    type: 'boolean',
                                    description: 'Only show events with level Warning',
                                },
                                criticalOnly: {
                                    type: 'boolean',
                                    description: 'Only show events with level Critical',
                                },
                                informationOnly: {
                                    type: 'boolean',
                                    description: 'Only show events with level Information',
                                },
                                verbose: {
                                    type: 'boolean',
                                    description: 'Enable verbose output during search',
                                },
                                showLogDiscovery: {
                                    type: 'boolean',
                                    description: 'Include detailed log discovery information in results',
                                },
                                skipSecurityLog: {
                                    type: 'boolean',
                                    description: 'Skip the Security log (useful if access is denied)',
                                },
                                includeSystemLogs: {
                                    type: 'boolean',
                                    description: 'Include only system logs (System, Security, Application, Setup)',
                                },
                                includeApplicationLogs: {
                                    type: 'boolean',
                                    description: 'Include only application-related logs',
                                },
                                includeCustomLogs: {
                                    type: 'boolean',
                                    description: 'Include only custom/third-party logs',
                                },
                            },
                        },
                    }
                ],
            };
        });
        this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
            const { name, arguments: args } = request.params;
            try {
                switch (name) {
                    case 'get_system_diagnostics':
                        return await diagnostics.getSystemDiagnostics(args);
                    case 'get_shutdown_events':
                        return await diagnostics.getShutdownEvents(args);
                    case 'get_bsod_events':
                        return await diagnostics.getBSODEvents(args);
                    case 'get_system_uptime':
                        return await diagnostics.getSystemUptime();
                    case 'analyze_system_stability':
                        return await diagnostics.analyzeSystemStability(args);
                    case 'search_registry':
                        return await registry.searchRegistry(args);
                    case 'analyze_startup_programs':
                        return await registry.analyzeStartupPrograms();
                    case 'scan_system_components':
                        return await registry.scanSystemComponents();
                    case 'find_orphaned_entries':
                        return await registry.findOrphanedEntries();
                    case 'get_registry_health':
                        return await registry.getRegistryHealth();
                    case 'scan_security_risks':
                        return await registry.scanSecurityRisks();
                    case 'list_processes':
                        return await apps.listProcesses(args);
                    case 'kill_process':
                        return await apps.killProcess(args);
                    case 'start_process':
                        return await apps.startProcess(args);
                    case 'list_installed_apps':
                        return await apps.listInstalledApps(args);
                    case 'hardware_monitor':
                        return await hardware.hardwareMonitor.execute(args);
                    case 'event_viewer_analyzer':
                        return await eventViewer.eventViewerAnalyzer(args);
                    case 'event_viewer_search':
                        return await eventViewerSearch.eventViewerSearch.execute(args);
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
    async run() {
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
        console.error('Windows Diagnostics MCP server running on stdio');
    }
}
const server = new WindowsDiagnosticsServer();
server.run().catch(console.error);
//# sourceMappingURL=index.js.map