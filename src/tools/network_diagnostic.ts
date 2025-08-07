import { runPowerShellScript } from '../utils.js';
import * as AllTypes from '../types.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HARDWARE_MONITOR_SCRIPT_PATH = path.resolve(__dirname, '../powershell_scripts/hardware_monitor.ps1');
const HARDWARE_MONITOR_SCRIPT = fs.readFileSync(HARDWARE_MONITOR_SCRIPT_PATH, 'utf-8');

export async function hardwareMonitor(args: AllTypes.HardwareMonitorParams) {
    const params = {
        checkTemperatures: args.checkTemperatures,
        checkFanSpeeds: args.checkFanSpeeds,
        checkSmartStatus: args.checkSmartStatus,
        checkMemoryHealth: args.checkMemoryHealth
    };
    
    const result = await runPowerShellScript(HARDWARE_MONITOR_SCRIPT, params) as AllTypes.HardwareMonitorOutput;
    
    return {
        content: [
            {
                type: 'text',
                text: `# Hardware Health Report\n\n## Temperatures\n${(result.Temperatures || []).map(temp => `- **${temp.Sensor}**: ${temp.TemperatureC}°C`).join('\n') || 'No temperature data available'}\n\n## Fan Speeds\n${(result.FanSpeeds || []).map(fan => `- **${fan.Fan}**: ${fan.SpeedRPM} RPM`).join('\n') || 'No fan data available'}`,
            },
        ],
    };
}