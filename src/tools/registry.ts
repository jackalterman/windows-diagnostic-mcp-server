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
              r => `- **Path**: ${r.Path}
  **Type**: ${r.Type}
  **Match**: ${r.Match}
  **Found**: ${r.Found || 'N/A'}
  **Value**: ${r.ValueName || 'N/A'}
  **Data**: ${r.ValueData || 'N/A'}`
            )
            .join('\n\n')
        : 'No results found.';
  
    return {
      content: [
        {
          type: 'text',
          text: `# Registry Search Results for "${searchTerm}"

${searchResultsText}`,
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
          text: `# Startup Program Analysis

${result.StartupPrograms && result.StartupPrograms.length > 0 ? result.StartupPrograms.map(p => `- **Name**: ${p.Name}
  **Command**: ${p.Command}
  **Location**: ${p.Location}
  **User**: ${p.User}
  **Verified**: ${p.Verified}
  **Suspicious**: ${p.Suspicious}`).join('\n\n') : 'No startup programs found.'}`,
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
          text: `# System Component Scan

${result.SystemComponents && result.SystemComponents.length > 0 ? result.SystemComponents.map(c => `- **Type**: ${c.Type}
  **Name**: ${c.Name}
  **Issue**: ${c.Issue}
  **Details**: ${c.Details}`).join('\n\n') : 'No issues found with system components.'}`,
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
          text: `# Orphaned Registry Entries

${result.OrphanedEntries && result.OrphanedEntries.length > 0 ? result.OrphanedEntries.map(o => `- **Path**: ${o.Path}
  **Type**: ${o.Type}`).join('\n\n') : 'No orphaned entries found.'}`,
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
          text: `# Registry Health Assessment

- **Score**: ${result.RegistryHealth?.Score}/100
- **Rating**: ${result.RegistryHealth?.Rating}
- **Issues Found**: ${result.RegistryHealth?.IssuesFound}

## Recommendations
${result.RegistryHealth && result.RegistryHealth.Recommendations && result.RegistryHealth.Recommendations.length > 0 ? result.RegistryHealth.Recommendations.map(r => `- ${r}`).join('\n\n') : 'No recommendations.'}`,
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
          text: `# Security Risk Scan

${result.SecurityFindings && result.SecurityFindings.length > 0 ? result.SecurityFindings.map(f => `- **ID**: ${f.ID}
  **Severity**: ${f.Severity}
  **Description**: ${f.Description}
  **Details**: ${f.Details}
  **Recommendation**: ${f.Recommendation}`).join('\n\n') : 'No security risks found.'}`,
        },
      ],
    };
  }
