import { runPowerShellScript } from '../utils.js';
import * as AllTypes from '../types.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REGISTRY_SCRIPT_PATH = path.resolve(__dirname, '../powershell_scripts/windows_registry.ps1');
const REGISTRY_SCRIPT = fs.readFileSync(REGISTRY_SCRIPT_PATH, 'utf-8');

export async function searchRegistry(args: { searchTerm?: string; maxResults?: number }) {
    const searchTerm = args.searchTerm ?? '';
    const maxResults = args.maxResults ?? 50;
  
    const result = await runPowerShellScript(
      REGISTRY_SCRIPT,
      {
        SearchTerm: searchTerm,
        MaxResults: maxResults,
        JsonOutput: true,
      }
    ) as AllTypes.RegistryDiagnosticResults;
  
    const searchResultsText =
      result.SearchResults && result.SearchResults.length > 0
        ? result.SearchResults
            .map(
              r => `- **Hive**: ${r.Hive}\n  **Key**: ${r.KeyPath}\n  **Value**: ${r.ValueName}\n  **Data**: ${r.ValueData}`
            )
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
  
  
  export async function analyzeStartupPrograms() {
    const result = await runPowerShellScript(REGISTRY_SCRIPT, { ScanStartup: true, JsonOutput: true }) as AllTypes.RegistryDiagnosticResults;
    return {
      content: [
        {
          type: 'text',
          text: `# Startup Program Analysis\n\n${result.StartupPrograms && result.StartupPrograms.length > 0 ? result.StartupPrograms.map(p => `- **Name**: ${p.Name}\n  **Command**: ${p.Command}\n  **Location**: ${p.Location}\n  **User**: ${p.User}\n  **Verified**: ${p.Verified}\n  **Suspicious**: ${p.Suspicious}`).join('\n\n') : 'No startup programs found.'}`,
        },
      ],
    };
  }
  
  export async function scanSystemComponents() {
    const result = await runPowerShellScript(REGISTRY_SCRIPT, { ScanServices: true, ScanUninstall: true, ScanFileAssoc: true, ScanDrivers: true, JsonOutput: true }) as AllTypes.RegistryDiagnosticResults;
    return {
      content: [
        {
          type: 'text',
          text: `# System Component Scan\n\n${result.SystemComponents && result.SystemComponents.length > 0 ? result.SystemComponents.map(c => `- **Type**: ${c.Type}\n  **Name**: ${c.Name}\n  **Issue**: ${c.Issue}\n  **Details**: ${c.Details}`).join('\n\n') : 'No issues found with system components.'}`,
        },
      ],
    };
  }
  
  export async function findOrphanedEntries() {
    const result = await runPowerShellScript(REGISTRY_SCRIPT, { FindOrphaned: true, JsonOutput: true }) as AllTypes.RegistryDiagnosticResults;
    return {
      content: [
        {
          type: 'text',
          text: `# Orphaned Registry Entries\n\n${result.OrphanedEntries && result.OrphanedEntries.length > 0 ? result.OrphanedEntries.map(o => `- **Path**: ${o.Path}\n  **Type**: ${o.Type}`).join('\n\n') : 'No orphaned entries found.'}`,
        },
      ],
    };
  }
  
  export async function getRegistryHealth() {
    const result = await runPowerShellScript(REGISTRY_SCRIPT, { JsonOutput: true }) as AllTypes.RegistryDiagnosticResults;
    return {
      content: [
        {
          type: 'text',
          text: `# Registry Health Assessment\n\n- **Score**: ${result.RegistryHealth?.Score}/100\n- **Rating**: ${result.RegistryHealth?.Rating}\n- **Issues Found**: ${result.RegistryHealth?.IssuesFound}\n\n## Recommendations\n${result.RegistryHealth && result.RegistryHealth.Recommendations.length > 0 ? result.RegistryHealth.Recommendations.map(r => `- ${r}`).join('\n') : 'No recommendations.'}`,
        },
      ],
    };
  }
  
  export async function scanSecurityRisks() {
    const result = await runPowerShellScript(REGISTRY_SCRIPT, { SecurityScan: true, JsonOutput: true }) as AllTypes.RegistryDiagnosticResults;
    return {
      content: [
        {
          type: 'text',
          text: `# Security Risk Scan\n\n${result.SecurityFindings && result.SecurityFindings.length > 0 ? result.SecurityFindings.map(f => `- **ID**: ${f.ID}\n  **Severity**: ${f.Severity}\n  **Description**: ${f.Description}\n  **Details**: ${f.Details}\n  **Recommendation**: ${f.Recommendation}`).join('\n\n') : 'No security risks found.'}`,
        },
      ],
    };
  }
