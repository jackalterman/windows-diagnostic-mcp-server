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

        // Format SMART status with detailed information
        const smartStatusText = result.SMARTStatus && result.SMARTStatus.length > 0
            ? result.SMARTStatus.map(s => {
                let driveInfo = `- **${s.Disk}**: ${s.Status}`;
                
                // Basic information
                if (s.Attributes.Size) driveInfo += ` (${s.Attributes.Size}GB)`;
                if (s.Attributes.Interface) driveInfo += ` - ${s.Attributes.Interface}`;
                if (s.Manufacturer) driveInfo += ` - ${s.Manufacturer}`;
                
                // Additional details on new lines for better readability
                const details = [];
                if (s.SerialNumber) details.push(`  - Serial: ${s.SerialNumber}`);
                if (s.FirmwareVersion) details.push(`  - Firmware: ${s.FirmwareVersion}`);
                if (s.MediaType) details.push(`  - Media Type: ${s.MediaType}`);
                if (s.Attributes.Partitions) details.push(`  - Partitions: ${s.Attributes.Partitions}`);
                if (s.Attributes.Status) details.push(`  - Status: ${s.Attributes.Status}`);
                if (s.Attributes.BytesPerSector) details.push(`  - Sector Size: ${s.Attributes.BytesPerSector} bytes`);
                if (s.Attributes.TotalSectors) details.push(`  - Total Sectors: ${s.Attributes.TotalSectors.toLocaleString()}`);
                if (s.Attributes.CapabilityDescriptions && s.Attributes.CapabilityDescriptions.length > 0) {
                    details.push(`  - Capabilities: ${s.Attributes.CapabilityDescriptions.join(', ')}`);
                }
                if (s.Attributes.InstallDate) details.push(`  - Install Date: ${s.Attributes.InstallDate}`);
                
                if (details.length > 0) {
                    driveInfo += '\n' + details.join('\n');
                }
                
                return driveInfo;
              }).join('\n\n')
            : 'No drive health data available.';

// Format memory health
const memoryHealthText = result.MemoryHealth
    ? `- **Status**: ${result.MemoryHealth.Status}
${result.MemoryHealth.TotalMemoryGB ? `- **Total Memory**: ${result.MemoryHealth.TotalMemoryGB}GB` : ''}
${result.MemoryHealth.UsedMemoryGB ? `- **Used Memory**: ${result.MemoryHealth.UsedMemoryGB}GB` : ''}
${result.MemoryHealth.FreeMemoryGB ? `- **Free Memory**: ${result.MemoryHealth.FreeMemoryGB}GB` : ''}
${result.MemoryHealth.UsagePercent ? `- **Usage**: ${result.MemoryHealth.UsagePercent}%` : ''}
${result.MemoryHealth.RAMModules && result.MemoryHealth.RAMModules.length > 0 
    ? `\n**RAM Modules:**\n${result.MemoryHealth.RAMModules.map((module, index) => 
        `  ${index + 1}. **${module.DeviceLocator || 'Unknown Slot'}**: ${module.CapacityGB}GB` +
        `${module.Speed ? ` @ ${module.Speed}MHz` : ''}` +
        `${module.Manufacturer ? ` (${module.Manufacturer})` : ''}` +
        `${module.PartNumber ? ` - ${module.PartNumber}` : ''}`
      ).join('\n')}` 
    : ''}
${result.MemoryHealth.Errors && result.MemoryHealth.Errors.length > 0 
    ? `\n- **Errors**: ${result.MemoryHealth.Errors.join(', ')}` 
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