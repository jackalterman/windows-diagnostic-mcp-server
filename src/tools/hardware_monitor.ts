import { runPowerShellScript } from '../utils.js';
import * as AllTypes from '../types.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HARDWARE_SCRIPT_PATH = path.resolve(__dirname, '../powershell_scripts/hardware_monitor.ps1');
const HARDWARE_SCRIPT = fs.readFileSync(HARDWARE_SCRIPT_PATH, 'utf-8');

export async function hardwareMonitor(args: {
    checkTemperatures?: boolean;
    checkFanSpeeds?: boolean;
    checkSmartStatus?: boolean;
    checkMemoryHealth?: boolean;
    debug?: boolean;
}) {
    const checkTemperatures = args.checkTemperatures ?? true;
    const checkFanSpeeds = args.checkFanSpeeds ?? true;
    const checkSmartStatus = args.checkSmartStatus ?? true;
    const checkMemoryHealth = args.checkMemoryHealth ?? true;
    const debug = args.debug ?? false;

    try {
        const result = await runPowerShellScript(
            HARDWARE_SCRIPT,
            {
                checkTemperatures,
                checkFanSpeeds,
                checkSmartStatus,
                checkMemoryHealth,
                debug,
                JsonOutput: true,
            }
        ) as AllTypes.HardwareMonitorOutput;

        // Format temperature sensors
        const temperaturesText = result.Temperatures && result.Temperatures.length > 0
            ? result.Temperatures.map(t => `- **${t.Sensor}**: ${t.TemperatureC}°C`).join('\n')
            : 'No temperature sensors found.';

        // Format fan speeds
        const fanSpeedsText = result.FanSpeeds && result.FanSpeeds.length > 0
            ? result.FanSpeeds.map(f => `- **${f.Fan}**: ${f.SpeedRPM} RPM`).join('\n')
            : 'No fan speed data available.';

        // Format SMART status
        const smartStatusText = result.SMARTStatus && result.SMARTStatus.length > 0
            ? result.SMARTStatus.map(s => {
                const sizeInfo = s.Attributes.Size ? ` (${s.Attributes.Size}GB)` : '';
                const usageInfo = s.Attributes.Usage ? ` - ${s.Attributes.Usage}% used` : '';
                const interfaceInfo = s.Attributes.Interface ? ` - ${s.Attributes.Interface}` : '';
                return `- **${s.Disk}**: ${s.Status}${sizeInfo}${usageInfo}${interfaceInfo}`;
              }).join('\n')
            : 'No drive health data available.';

// Format memory health
const memoryHealthText = result.MemoryHealth
    ? `- **Status**: ${result.MemoryHealth.Status}
${result.MemoryHealth.TotalMemoryGB ? `- **Total Memory**: ${result.MemoryHealth.TotalMemoryGB}GB` : ''}
${result.MemoryHealth.UsedMemoryGB ? `- **Used Memory**: ${result.MemoryHealth.UsedMemoryGB}GB` : ''}
${result.MemoryHealth.FreeMemoryGB ? `- **Free Memory**: ${result.MemoryHealth.FreeMemoryGB}GB` : ''}
${result.MemoryHealth.UsagePercent ? `- **Usage**: ${result.MemoryHealth.UsagePercent}%` : ''}
${result.MemoryHealth.Errors && result.MemoryHealth.Errors.length > 0 
    ? `- **Errors**: ${result.MemoryHealth.Errors.join(', ')}` 
    : ''}`
    : 'Memory health data not available.';

        // Format errors
        const errorsText = result.Errors && result.Errors.length > 0
            ? `## Errors\n${result.Errors.map(e => `- ${e}`).join('\n')}`
            : '';

        return {
            content: [
                {
                    type: 'text',
                    text: `# Hardware Monitor Results

## Temperature Sensors
${temperaturesText}

## Fan Speeds
${fanSpeedsText}

## Drive Health (SMART Status)
${smartStatusText}

## Memory Health
${memoryHealthText}

${errorsText}`.trim(),
                },
            ],
        };
    } catch (error) {
        return {
            content: [
                {
                    type: 'text',
                    text: `# Hardware Monitor Error

Failed to collect hardware information: ${error instanceof Error ? error.message : String(error)}`,
                },
            ],
        };
    }
}