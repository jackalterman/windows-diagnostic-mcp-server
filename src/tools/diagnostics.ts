import { runPowerShellScript } from '../utils.js';
import * as AllTypes from '../types.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DIAGNOSTIC_SCRIPT_PATH = path.resolve(__dirname, '../powershell_scripts/diagnostic.ps1');
const DIAGNOSTIC_SCRIPT = fs.readFileSync(DIAGNOSTIC_SCRIPT_PATH, 'utf-8');

export async function getSystemDiagnostics(args: { daysBack?: number; detailed?: boolean }) {
    const daysBack = args?.daysBack || 7;
    const detailed = args?.detailed || false;
    
    const params = {
      DaysBack: daysBack,
      JsonOutput: true,
      ...(detailed && { Detailed: true })
    };

    const result = await runPowerShellScript(DIAGNOSTIC_SCRIPT, params) as AllTypes.DiagnosticResults;

    return {
      content: [
        {
          type: 'text',
          text: `# Windows System Diagnostics Report\n\n## Summary\n- **Analysis Period**: ${result.Summary.AnalysisPeriodDays} days\n- **Total Events**: ${result.Summary.TotalEventsAnalyzed}\n- **Critical BSOD Events**: ${result.Summary.CriticalBSODCount}\n- **Unexpected Shutdowns**: ${result.Summary.UnexpectedShutdownCount}\n- **Application Crashes**: ${result.Summary.TotalApplicationCrashes}\n- **Generated**: ${result.Summary.GeneratedAt}\n\n## System Information\n- **OS**: ${result.SystemInfo.OSVersion}\n- **Last Boot**: ${result.SystemInfo.LastBootTime}\n- **Current Uptime**: ${result.SystemInfo.CurrentUptimeDays} days, ${result.SystemInfo.CurrentUptimeHours} hours, ${result.SystemInfo.CurrentUptimeMinutes} minutes\n- **Total Memory**: ${result.SystemInfo.TotalMemoryGB} GB\n- **Reboots in Period**: ${result.SystemInfo.RebootCountInPeriod}\n\n## Critical Events\n${result.BSODEvents.length > 0 ? `### BSOD Events (⚠️ Critical)\n${result.BSODEvents.map((e: AllTypes.EventInfo) => `- **${e.Time}**: ${e.Description} (Event ID: ${e.EventID})`).join('\n')}` : '### BSOD Events\n- No BSOD events found ✅'}\n\n${result.ShutdownEvents.filter((e: AllTypes.EventInfo) => e.EventID === 6008).length > 0 ? `### Unexpected Shutdowns (⚠️ Warning)\n${result.ShutdownEvents.filter((e: AllTypes.EventInfo) => e.EventID === 6008).map((e: AllTypes.EventInfo) => `- **${e.Time}**: ${e.Description}`).join('\n')}` : '### Unexpected Shutdowns\n- No unexpected shutdowns found ✅'}\n\n## Application Crashes\n${result.ApplicationCrashes.length > 0 ? result.ApplicationCrashes.map((c: AllTypes.ApplicationCrash) => `- **${c.Application}**: ${c.CrashCount} crashes (Latest: ${c.LatestCrash})`).join('\n') : '- No application crashes found ✅'}\n\n## Hardware & Driver Issues\n${result.HardwareErrors.length > 0 ? `### Hardware Errors\n${result.HardwareErrors.map((e: AllTypes.HardwareError) => `- **${e.Time}**: ${e.Source}`).join('\n')}` : '### Hardware Errors\n- No hardware errors found ✅'}\n\n${result.DriverIssues.length > 0 ? `### Driver Issues\n${result.DriverIssues.map((d: AllTypes.DriverIssue) => `- **${d.DriverService}**: ${d.IssueCount} issues`).join('\n')}` : '### Driver Issues\n- No driver issues found ✅'}\n\n## Memory Dumps\n${result.MemoryDumps.length > 0 ? result.MemoryDumps.map((d: AllTypes.MemoryDump) => `- **${d.Type} Dump**: ${d.Path} (Last Modified: ${d.LastWrite}, Size: ${d.SizeMB || d.SizeKB} ${d.SizeMB ? 'MB' : 'KB'})`).join('\n') : '- No memory dumps found'}\n\n## Recent System Events\n${result.ShutdownEvents.slice(0, 5).map((e: AllTypes.EventInfo) => `- **${e.Time}**: ${e.Description} (Event ID: ${e.EventID})`).join('\n')}`,
        },
      ],
    };
  }

  export async function getShutdownEvents(args: { daysBack?: number }) {
    const daysBack = args?.daysBack || 7;
    const result = await runPowerShellScript(DIAGNOSTIC_SCRIPT, { DaysBack: daysBack, JsonOutput: true }) as AllTypes.DiagnosticResults;

    return {
      content: [
        {
          type: 'text',
          text: `# Shutdown and Reboot Events (Last ${daysBack} days)\n\n${result.ShutdownEvents.length > 0 ? 
  result.ShutdownEvents.map((e: AllTypes.EventInfo) => `- **${e.Time}**: ${e.Description} (Event ID: ${e.EventID}, Source: ${e.Source})`).join('\n') 
  : 'No shutdown/reboot events found in the specified period.'}\n\n**Total Events**: ${result.ShutdownEvents.length}\n**Unexpected Shutdowns**: ${result.ShutdownEvents.filter((e: AllTypes.EventInfo) => e.EventID === 6008).length}`,
        },
      ],
    };
  }

  export async function getBSODEvents(args: { daysBack?: number }) {
    const daysBack = args?.daysBack || 7;
    const result = await runPowerShellScript(DIAGNOSTIC_SCRIPT, { DaysBack: daysBack, JsonOutput: true }) as AllTypes.DiagnosticResults;

    return {
      content: [
        {
          type: 'text',
          text: `# Blue Screen of Death (BSOD) Events (Last ${daysBack} days)\n\n${result.BSODEvents.length > 0 ? 
  `⚠️ **CRITICAL**: ${result.BSODEvents.length} BSOD event(s) found!\n\n` + result.BSODEvents.map((e: AllTypes.EventInfo) => `- **${e.Time}**: ${e.Description} (Event ID: ${e.EventID}, Source: ${e.Source})\n  Details: ${e.Details.substring(0, 200)}...`).join('\n\n')
  : '✅ No BSOD events found in the specified period.'}`,
        },
      ],
    };
  }

  export async function getSystemUptime() {
    const result = await runPowerShellScript(DIAGNOSTIC_SCRIPT, { DaysBack: 1, JsonOutput: true }) as AllTypes.DiagnosticResults;

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

  export async function analyzeSystemStability(args: { daysBack?: number }) {
    const daysBack = args?.daysBack || 30;
    const result = await runPowerShellScript(DIAGNOSTIC_SCRIPT, { DaysBack: daysBack, JsonOutput: true }) as AllTypes.DiagnosticResults;

    const bsodCount = result.BSODEvents.length;
    const unexpectedShutdowns = result.ShutdownEvents.filter((e: AllTypes.EventInfo) => e.EventID === 6008).length;
    const totalCrashes = result.Summary.TotalApplicationCrashes || 0;
    const hardwareErrors = result.HardwareErrors.length;

    let stabilityScore = 100;
    const recommendations: string[] = [];
    const issues: string[] = [];

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

    let stabilityRating: string;
    if (stabilityScore >= 90) stabilityRating = 'Excellent ✅';
    else if (stabilityScore >= 75) stabilityRating = 'Good 👍';
    else if (stabilityScore >= 50) stabilityRating = 'Fair ⚠️';
    else stabilityRating = 'Poor ❌';

    return {
      content: [
        {
          type: 'text',
          text: `# System Stability Analysis (Last ${daysBack} days)\n\n## Overall Stability Score: ${stabilityScore}/100 (${stabilityRating})\n\n## Issues Detected\n${issues.length > 0 ? issues.map(issue => `- ${issue}`).join('\n') : '- No major issues detected ✅'}\n\n## Recommendations\n${recommendations.length > 0 ? recommendations.map(rec => `- ${rec}`).join('\n') : '- System appears stable, continue regular maintenance'}\n\n## Key Metrics\n- **BSOD Events**: ${bsodCount}\n- **Unexpected Shutdowns**: ${unexpectedShutdowns}\n- **Application Crashes**: ${totalCrashes}\n- **Hardware Errors**: ${hardwareErrors}\n- **Current Uptime**: ${result.SystemInfo.CurrentUptimeDays} days\n\n## Additional Actions\n- Run DISM health check: \`DISM /Online /Cleanup-Image /RestoreHealth\`\n- Check Windows Update for pending updates\n- Review Event Viewer for additional details\n- Consider hardware diagnostics if issues persist`,
        },
      ],
    };
  }
