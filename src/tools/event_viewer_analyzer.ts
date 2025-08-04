import { runPowerShellScript } from '../utils.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EVENT_VIEWER_SCRIPT_PATH = path.resolve(__dirname, '../powershell_scripts/event_viewer_analyzer.ps1');
const EVENT_VIEWER_SCRIPT = fs.readFileSync(EVENT_VIEWER_SCRIPT_PATH, 'utf-8');

export interface EventViewerAnalyzerTool {
  logNames?: string[];
  searchTerms?: string[];
  eventIds?: number[];
  sources?: string[];
  hours?: number;
  days?: number;
  startTime?: string;
  endTime?: string;
  errorsOnly?: boolean;
  warningsOnly?: boolean;
  criticalOnly?: boolean;
  securityAnalysis?: boolean;
  detailed?: boolean;
  exportJson?: boolean;
  exportCsv?: boolean;
  outputPath?: string;
  maxEvents?: number;
  showStats?: boolean;
  groupBySource?: boolean;
  timelineView?: boolean;
}

export async function eventViewerAnalyzer(
  options: EventViewerAnalyzerTool,
): Promise<any> {
  try {
    const result = await runPowerShellScript(EVENT_VIEWER_SCRIPT, options as any);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (error) {
    return {
      content: [
        {
          type: 'text',
          text: `Error executing event_viewer_analyzer: ${
            error instanceof Error ? error.message : String(error)
          }`,
        },
      ],
    };
  }
}
