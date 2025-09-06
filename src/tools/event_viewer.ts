import { runPowerShellScript } from '../utils.js';
import * as AllTypes from '../types.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EVENT_VIEWER_SCRIPT_PATH = path.resolve(__dirname, '../powershell_scripts/event_viewer.ps1');
const EVENT_VIEWER_SCRIPT = fs.readFileSync(EVENT_VIEWER_SCRIPT_PATH, 'utf-8');

export async function eventViewer(args: {
  // Search parameters
  SearchKeyword?: string;
  EventIDs?: number[];
  Sources?: string[];
  LogNames?: string[];
  Hours?: number;
  Days?: number;
  StartTime?: string;
  EndTime?: string;
  MaxEventsPerLog?: number;
  IncludeDisabledLogs?: boolean;
  ErrorsOnly?: boolean;
  WarningsOnly?: boolean;
  CriticalOnly?: boolean;
  InformationOnly?: boolean;
  SkipSecurityLog?: boolean;
  IncludeSystemLogs?: boolean;
  IncludeApplicationLogs?: boolean;
  DeepSearch?: boolean;
  Detailed?: boolean;
  SearchTerms?: string[];
  SecurityAnalysis?: boolean;
  ExportJson?: boolean;
  ExportCsv?: boolean;
  OutputPath?: string;
}) {
  try {
    // Convert number arrays to string arrays for PowerShell compatibility
    const powershellArgs = {
      ...args,
      EventIDs: args.EventIDs?.map(id => id.toString())
    };

    const result = await runPowerShellScript(
      EVENT_VIEWER_SCRIPT,
      powershellArgs
    ) as AllTypes.UnifiedEventViewerOutput;

    // Format the main summary
    let summaryText = `# Event Viewer Analysis Results

## Analysis Period
- **Start Time**: ${result.AnalysisPeriod?.StartTime || 'N/A'}
- **End Time**: ${result.AnalysisPeriod?.EndTime || 'N/A'}
- **Duration**: ${result.AnalysisPeriod?.Duration || 'N/A'}

## Search Results
- **Total Events Found**: ${result.SearchResults?.TotalEventsFound || 0}
- **Logs Searched**: ${result.LogDiscovery?.LogsSearched?.length || 0}
- **Events by Level**: ${result.SearchResults?.EventsByLevel ? Object.entries(result.SearchResults.EventsByLevel).map(([level, count]) => `${level}: ${count}`).join(', ') : 'N/A'}`;

    // Add log discovery info if available
    if (result.LogDiscovery) {
      summaryText += `

## Log Discovery
- **Total Logs Found**: ${result.LogDiscovery.TotalLogsFound}
- **Enabled Logs**: ${result.LogDiscovery.EnabledLogs}
- **Accessible Logs**: ${result.LogDiscovery.AccessibleLogs}`;
    }

    // Add security analysis if available
    if (result.SecurityAnalysis) {
      summaryText += `

## Security Analysis
- **Successful Logons**: ${result.SecurityAnalysis.LogonEvents?.Successful || 0}
- **Failed Logons**: ${result.SecurityAnalysis.LogonEvents?.Failed || 0}
- **Account Lockouts**: ${result.SecurityAnalysis.AccountLockouts?.length || 0}
- **Policy Changes**: ${result.SecurityAnalysis.PolicyChanges?.length || 0}`;
      
      if (result.SecurityAnalysis.SuspiciousActivity && result.SecurityAnalysis.SuspiciousActivity.length > 0) {
        summaryText += `
- **Suspicious Activities**: ${result.SecurityAnalysis.SuspiciousActivity.length} detected`;
      }
    }

    // Add error patterns if available
    if (result.ErrorPatterns) {
      summaryText += `

## Error Patterns
- **Total Errors**: ${result.ErrorPatterns.TotalErrors}
- **Total Warnings**: ${result.ErrorPatterns.TotalWarnings}
- **Recent Error Count**: ${result.ErrorPatterns.RecentErrorCount}`;
    }

    // Add top events if available
    if (result.Events && result.Events.length > 0) {
      summaryText += `

## Recent Events (Top ${Math.min(5, result.Events.length)})`;
      result.Events.slice(0, 5).forEach((event, index) => {
        summaryText += `

### Event ${index + 1}
- **Time**: ${event.TimeCreated}
- **Log**: ${event.LogName}
- **Level**: ${event.LevelDisplayName}
- **ID**: ${event.Id}
- **Source**: ${event.ProviderName}
- **Message**: ${event.Message ? event.Message.substring(0, 200) + (event.Message.length > 200 ? '...' : '') : 'N/A'}`;
      });
    }

    // Add recommendations if available
    if (result.Recommendations && result.Recommendations.length > 0) {
      summaryText += `

## Recommendations
${result.Recommendations.map(r => `- ${r}`).join('\n')}`;
    }

    // Add errors and warnings
    if (result.Errors && result.Errors.length > 0) {
      summaryText += `

## Errors
${result.Errors.map(e => `- ${e}`).join('\n')}`;
    }

    if (result.Warnings && result.Warnings.length > 0) {
      summaryText += `

## Warnings
${result.Warnings.map(w => `- ${w}`).join('\n')}`;
    }

    return {
      content: [
        {
          type: 'text',
          text: summaryText,
        },
      ],
    };
  } catch (error) {
    return {
      content: [
        {
          type: 'text',
          text: `# Event Viewer Error

Failed to analyze events: ${error instanceof Error ? error.message : String(error)}`,
        },
      ],
    };
  }
}

// Legacy function names for backward compatibility
export const eventViewerSearch = eventViewer;
export const eventViewerAnalyzer = eventViewer;