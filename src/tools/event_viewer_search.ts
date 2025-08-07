import { z } from 'zod';
import { Tool } from '../types.js';
import { runPowerShellScript } from '../utils.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EVENT_VIEWER_SEARCH_SCRIPT_PATH = path.resolve(__dirname, '../powershell_scripts/event_viewer_search.ps1');
const EVENT_VIEWER_SEARCH_SCRIPT = fs.readFileSync(EVENT_VIEWER_SEARCH_SCRIPT_PATH, 'utf-8');

// Zod schema for the event viewer search parameters
export const eventViewerSearchParamsSchema = z.object({
  searchKeyword: z.string().optional().describe('Keyword to search for in event messages'),
  eventIds: z.array(z.number()).optional().describe('Specific event IDs to filter by'),
  sources: z.array(z.string()).optional().describe('Event sources/providers to filter by'),
  logNames: z.array(z.string()).optional().describe('Specific log names to search (if empty, searches all available logs)'),
  hours: z.number().optional().describe('Number of hours back to search (default: 24)'),
  days: z.number().optional().describe('Number of days back to search (overrides hours if specified)'),
  startTime: z.string().optional().describe('Start time for the search (format: "YYYY-MM-DDTHH:mm:ss")'),
  endTime: z.string().optional().describe('End time for the search (format: "YYYY-MM-DDTHH:mm:ss")'),
  maxEventsPerLog: z.number().optional().describe('Maximum number of events to return per log (default: 100)'),
  includeDisabledLogs: z.boolean().optional().describe('Include disabled logs in the search'),
  errorsOnly: z.boolean().optional().describe('Only show events with level Error'),
  warningsOnly: z.boolean().optional().describe('Only show events with level Warning'),
  criticalOnly: z.boolean().optional().describe('Only show events with level Critical'),
  informationOnly: z.boolean().optional().describe('Only show events with level Information'),
  verbose: z.boolean().optional().describe('Enable verbose output during search'),
  showLogDiscovery: z.boolean().optional().describe('Include detailed log discovery information in results'),
  skipSecurityLog: z.boolean().optional().describe('Skip the Security log (useful if access is denied)'),
  includeSystemLogs: z.boolean().optional().describe('Include only system logs (System, Security, Application, Setup)'),
  includeApplicationLogs: z.boolean().optional().describe('Include only application-related logs'),
  includeCustomLogs: z.boolean().optional().describe('Include only custom/third-party logs')
});

// Type definitions for the search results
export interface EventViewerSearchEvent {
  TimeCreated: string;
  LogName: string;
  Level: number;
  LevelDisplayName: string;
  Id: number;
  ProviderName: string;
  TaskDisplayName: string;
  Message: string;
  UserId: string;
  ProcessId: number;
  ThreadId: number;
  MachineName: string;
  RecordId: number;
}

export interface LogDiscoveryInfo {
  TotalLogsFound: number;
  EnabledLogs: number;
  DisabledLogs: number;
  AccessibleLogs: number;
  InaccessibleLogs: number;
  LogsSearched: Array<{
    LogName: string;
    EventsFound: number;
    SearchTime: number;
  }>;
  LogsSkipped: Array<{
    LogName: string;
    Reason: string;
    Error?: string;
  }>;
  AllLogs?: Array<{
    LogName: string;
    IsEnabled: boolean;
    RecordCount: number;
    FileSize: number;
    LastWriteTime: string;
  }>;
}

export interface SearchResults {
  TotalEventsFound: number;
  EventsByLog: Record<string, number>;
  EventsByLevel: Record<string, number>;
  EventsBySource: Record<string, number>;
  TopEventIDs: Array<{
    EventID: number;
    Count: number;
  }>;
}

export interface EventViewerSearchOutput {
  Timestamp: string;
  ComputerName: string;
  SearchCriteria: {
    Keyword: string;
    EventIDs: number[];
    Sources: string[];
    TimeRange: {
      StartTime: string;
      EndTime: string;
      Duration: string;
    };
    MaxEventsPerLog: number;
  };
  LogDiscovery: LogDiscoveryInfo;
  SearchResults: SearchResults;
  Events: EventViewerSearchEvent[];
  Errors: string[];
  Warnings: string[];
  Performance: {
    SearchDuration: number;
    LogsProcessed: number;
    AverageTimePerLog: number;
  };
}

// Type for the parameters
export type EventViewerSearchParams = z.infer<typeof eventViewerSearchParamsSchema>;

// The tool definition
export const eventViewerSearch: Tool = {
  name: 'event_viewer_search',
  description: 'Comprehensive Windows Event Viewer search tool that enumerates all available logs and searches across them for keywords, event IDs, or other criteria. This tool can discover and search all Windows event logs, not just the main four.',
  schema: eventViewerSearchParamsSchema,
  execute: async (params: EventViewerSearchParams): Promise<EventViewerSearchOutput> => {
    try {
      const result = await runPowerShellScript(EVENT_VIEWER_SEARCH_SCRIPT, params as any);
      return result;
    } catch (error) {
      throw new Error(`Error executing event_viewer_search: ${
        error instanceof Error ? error.message : String(error)
      }`);
    }
  }
}; 