import { Tool } from '../types.js';
import { runPowerShellScript } from '../utils.js';
import {
  HardwareMonitorOutput,
  HardwareMonitorParams,
  hardwareMonitorParamsSchema,
} from '../types.js';

export type { HardwareMonitorParams } from '../types.js';

export const hardwareMonitor: Tool = {
  name: 'hardware_monitor',
  description:
    'Monitors hardware health including temperatures, fan speeds, drive SMART status, and memory health.',
  schema: hardwareMonitorParamsSchema,
  execute: async (params: HardwareMonitorParams): Promise<HardwareMonitorOutput> => {
    const scriptOutput = await runPowerShellScript('hardware_monitor.ps1', params);
    return scriptOutput;
  },
};