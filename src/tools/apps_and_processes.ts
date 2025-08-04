import { runPowerShellScript } from '../utils.js';
import * as AllTypes from '../types.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const APPS_AND_PROCESSES_SCRIPT_PATH = path.resolve(__dirname, '../powershell_scripts/apps_and_processes.ps1');
const APPS_AND_PROCESSES_SCRIPT = fs.readFileSync(APPS_AND_PROCESSES_SCRIPT_PATH, 'utf-8');

export async function listProcesses(args: { filterName?: string; minCPU?: number; minMemoryMB?: number }) {
    const params = {
      FilterName: args.filterName,
      MinCPU: args.minCPU,
      MinMemoryMB: args.minMemoryMB,
      JsonOutput: true,
    };
    const result = await runPowerShellScript(APPS_AND_PROCESSES_SCRIPT, params) as AllTypes.AppsAndProcessesResults;
    return {
      content: [
        {
          type: 'text',
          text: `# Running Processes\n\n${result.RunningProcesses && result.RunningProcesses.length > 0 ? result.RunningProcesses.map(p => `- **Name**: ${p.Name}\n  **PID**: ${p.PID}\n  **CPU**: ${p.CPU}\n  **MemoryMB**: ${p.MemoryMB}\n  **User**: ${p.User}`).join('\n\n') : 'No running processes found.'}`,
        },
      ],
    };
  }

  export async function killProcess(args: { pid?: number; name?: string }) {
    const params = {
      KillPID: args.pid,
      KillName: args.name,
      JsonOutput: true,
    };
    const result = await runPowerShellScript(APPS_AND_PROCESSES_SCRIPT, params) as AllTypes.AppsAndProcessesResults;
    return {
      content: [
        {
          type: 'text',
          text: `# Kill Process Results\n\n${result.KilledProcesses && result.KilledProcesses.length > 0 ? result.KilledProcesses.map(p => p.Error ? `- **Error**: ${p.Error}` : `- **Killed**: PID ${p.PID}, Name ${p.Name}`).join('\n') : 'No processes killed.'}`,
        },
      ],
    };
  }

  export async function startProcess(args: { path: string }) {
    const params = {
      StartPath: args.path,
      JsonOutput: true,
    };
    const result = await runPowerShellScript(APPS_AND_PROCESSES_SCRIPT, params) as AllTypes.AppsAndProcessesResults;
    return {
      content: [
        {
          type: 'text',
          text: `# Start Process Result\n\n${result.StartedProcess ? (result.StartedProcess.Error ? `- **Error**: ${result.StartedProcess.Error}` : `- **Started**: Name ${result.StartedProcess.Name}, PID ${result.StartedProcess.PID}, Path ${result.StartedProcess.Path}`) : 'No process started.'}`,
        },
      ],
    };
  }

  export async function listInstalledApps(args: { appName?: string; publisher?: string }) {
    const params = {
      ListInstalledApps: true,
      AppName: args.appName,
      Publisher: args.publisher,
      JsonOutput: true,
    };
    const result = await runPowerShellScript(APPS_AND_PROCESSES_SCRIPT, params) as AllTypes.AppsAndProcessesResults;
    return {
      content: [
        {
          type: 'text',
          text: `# Installed Applications\n\n${result.InstalledApplications && result.InstalledApplications.length > 0 ? result.InstalledApplications.map(a => `- **Name**: ${a.Name}\n  **Version**: ${a.Version}\n  **Publisher**: ${a.Publisher}\n  **InstallDate**: ${a.InstallDate}`).join('\n\n') : 'No installed applications found.'}`,
        },
      ],
    };
  }
