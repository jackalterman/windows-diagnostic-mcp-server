#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import * as diagnostics from './tools/diagnostics.js';
import * as registry from './tools/registry.js';
import * as eventViewer from './tools/event_viewer.js';
import * as apps from './tools/apps_and_processes.js';
import { hardwareMonitor } from './tools/hardware_monitor.js';
import type { EventViewerParams, HardwareMonitorParams, SystemInfoParams } from './types.js';
import * as usageGuide from './tools/usage_guide_and_administrator_check.js';

class WindowsDiagnosticsServer {
  private server: Server;

  constructor() {
    this.server = new Server(
      {
        name: 'windows-diagnostics',
        version: '0.1.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();

    // Error handling
    this.server.onerror = (error) => console.error('[MCP Error]', error);
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  private setupToolHandlers() {
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
                debug: {
                  type: 'boolean',
                  description: 'Enable debug mode for detailed troubleshooting information',
                  default: false,
                },
              },
            },
          },
          {
            name: 'event_viewer',
            description: 'Comprehensive Windows Event Viewer tool that combines search and analysis capabilities. Can enumerate ALL available Windows event logs and search across them for keywords, event IDs, or other criteria, while also providing detailed security analysis, error pattern detection, and actionable recommendations.',
            inputSchema: {
              type: 'object',
              properties: {
                SearchKeyword: {
                  type: 'string',
                  description: 'Keyword to search for in event messages',
                },
                EventIDs: {
                  type: 'array',
                  items: { type: 'number' },
                  description: 'Specific event IDs to filter by',
                },
                Sources: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Event sources/providers to filter by',
                },
                LogNames: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Specific log names to search (if empty, searches all available logs)',
                },
                Hours: {
                  type: 'number',
                  description: 'Number of hours back to search (default: 24)',
                },
                Days: {
                  type: 'number',
                  description: 'Number of days back to search (overrides hours if specified)',
                },
                StartTime: {
                  type: 'string',
                  description: 'Start time for the search (format: "YYYY-MM-DDTHH:mm:ss")',
                },
                EndTime: {
                  type: 'string',
                  description: 'End time for the search (format: "YYYY-MM-DDTHH:mm:ss")',
                },
                MaxEventsPerLog: {
                  type: 'number',
                  description: 'Maximum number of events to return per log (default: 100)',
                },
                IncludeDisabledLogs: {
                  type: 'boolean',
                  description: 'Include disabled logs in the search',
                },
                ErrorsOnly: {
                  type: 'boolean',
                  description: 'Only show events with level Error',
                },
                WarningsOnly: {
                  type: 'boolean',
                  description: 'Only show events with level Warning',
                },
                CriticalOnly: {
                  type: 'boolean',
                  description: 'Only show events with level Critical',
                },
                InformationOnly: {
                  type: 'boolean',
                  description: 'Only show events with level Information',
                },
                Verbose: {
                  type: 'boolean',
                  description: 'Enable verbose output during search',
                },
                ShowLogDiscovery: {
                  type: 'boolean',
                  description: 'Include detailed log discovery information in results',
                },
                SkipSecurityLog: {
                  type: 'boolean',
                  description: 'Skip the Security log (useful if access is denied)',
                },
                IncludeSystemLogs: {
                  type: 'boolean',
                  description: 'Include only system logs (System, Security, Application, Setup)',
                },
                IncludeApplicationLogs: {
                  type: 'boolean',
                  description: 'Include only application-related logs',
                },
                IncludeCustomLogs: {
                  type: 'boolean',
                  description: 'Include only custom/third-party logs',
                },
                SearchTerms: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Alternative to searchKeyword - array of search terms',
                },
                SecurityAnalysis: {
                  type: 'boolean',
                  description: 'Perform detailed security analysis',
                },
                Detailed: {
                  type: 'boolean',
                  description: 'Include detailed analysis in results',
                },
                ExportJson: {
                  type: 'boolean',
                  description: 'Export results to JSON file',
                },
                ExportCsv: {
                  type: 'boolean',
                  description: 'Export results to CSV file',
                },
                OutputPath: {
                  type: 'string',
                  description: 'Output path for exported files',
                },
                MaxEvents: {
                  type: 'number',
                  description: 'Maximum total events to analyze (default: 1000)',
                },
                ShowStats: {
                  type: 'boolean',
                  description: 'Show detailed statistics',
                },
                GroupBySource: {
                  type: 'boolean',
                  description: 'Group results by event source',
                },
                TimelineView: {
                  type: 'boolean',
                  description: 'Include timeline view in results',
                },
                Debug: {
                  type: 'boolean',
                  description: 'Enable debug output for troubleshooting',
                },
              },
            },
          },
          {
            name: 'get_usage_guide_and_check_for_administrator',
            description: 'Check administrator privileges, domain status, PowerShell execution policy, and get diagnostic toolset usage guide. Essential first step for system diagnostics.',
            inputSchema: {
              type: 'object',
              properties: {
                FixExecutionPolicy: {
                  type: 'boolean',
                  description: 'Attempt to set PowerShell execution policy to RemoteSigned for current user',
                  default: false
                },
                ShowHelp: {
                  type: 'boolean',
                  description: 'Display detailed usage guide for the diagnostic toolset',
                  default: false
                },
                Detailed: {
                  type: 'boolean',
                  description: 'Include additional system information and context',
                  default: false
                }
              }
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
            return await diagnostics.getSystemDiagnostics(args as { daysBack?: number; detailed?: boolean });
          case 'get_shutdown_events':
            return await diagnostics.getShutdownEvents(args as { daysBack?: number });
          case 'get_bsod_events':
            return await diagnostics.getBSODEvents(args as { daysBack?: number });
          case 'get_system_uptime':
            return await diagnostics.getSystemUptime();
          case 'analyze_system_stability':
            return await diagnostics.analyzeSystemStability(args as { daysBack?: number });
          case 'search_registry':
            return await registry.searchRegistry(args as { searchTerm?: string; maxResults?: number });
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
            return await apps.listProcesses(args as { filterName?: string; minCPU?: number; minMemoryMB?: number });
          case 'kill_process':
            return await apps.killProcess(args as { pid?: number; name?: string });
          case 'start_process':
            return await apps.startProcess(args as { path: string });
          case 'list_installed_apps':
            return await apps.listInstalledApps(args as { appName?: string; publisher?: string });
          case 'hardware_monitor':
            return await hardwareMonitor(args as HardwareMonitorParams);
          case 'event_viewer':
            return await eventViewer.eventViewer(args as EventViewerParams);
          case 'get_usage_guide_and_check_for_administrator':
            return await usageGuide.getSystemInfo(args as SystemInfoParams);
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
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