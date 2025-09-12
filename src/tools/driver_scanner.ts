import { runPowerShellScript } from '../utils.js';
import * as AllTypes from '../types.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DRIVER_SCANNER_SCRIPT_PATH = path.resolve(__dirname, '../powershell_scripts/driver_scanner.ps1');
const DRIVER_SCANNER_SCRIPT = fs.readFileSync(DRIVER_SCANNER_SCRIPT_PATH, 'utf-8');

export async function scanDrivers(args: AllTypes.DriverScannerParams = {}) {
  const params = {
    DriverName: args.driverName || "",
    DeviceClass: args.deviceClass || "",
    Manufacturer: args.manufacturer || "",
    SignedOnly: args.signedOnly || false,
    UnsignedOnly: args.unsignedOnly || false,
    EnabledOnly: args.enabledOnly || false,
    DisabledOnly: args.disabledOnly || false,
    WithErrors: args.withErrors || false,
    CheckSecurity: args.checkSecurity || false,
    CheckVersions: args.checkVersions || false,
    CheckHealth: args.checkHealth || false,
    Detailed: args.detailed || false,
  };

  const result = await runPowerShellScript(DRIVER_SCANNER_SCRIPT, params) as AllTypes.DriverScannerOutput;

  // Format the output as markdown
  let output = `# Driver Scanner Results\n\n`;
  
  // Summary section
  output += `## Summary\n`;
  output += `- **Total Drivers**: ${result.Summary.TotalDrivers}\n`;
  output += `- **Signed Drivers**: ${result.Summary.SignedDrivers}\n`;
  output += `- **Unsigned Drivers**: ${result.Summary.UnsignedDrivers}\n`;
  output += `- **Enabled Drivers**: ${result.Summary.EnabledDrivers}\n`;
  output += `- **Disabled Drivers**: ${result.Summary.DisabledDrivers}\n`;
  
  if (args.checkSecurity) {
    output += `- **Security Issues**: ${result.Summary.SecurityIssues}\n`;
  }
  
  if (args.checkVersions) {
    output += `- **Outdated Drivers**: ${result.Summary.OutdatedDrivers}\n`;
  }
  
  if (args.checkHealth) {
    output += `- **Drivers with Errors**: ${result.Summary.DriversWithErrors}\n`;
  }
  
  output += `\n`;

  // Security Analysis section
  if (args.checkSecurity && result.SecurityAnalysis.UnsignedDrivers.length > 0) {
    output += `## Security Analysis\n\n`;
    output += `### Unsigned Drivers (${result.SecurityAnalysis.UnsignedDrivers.length})\n\n`;
    
    result.SecurityAnalysis.UnsignedDrivers.forEach((driver, index) => {
      output += `**${index + 1}. ${driver.DriverName}**\n`;
      output += `- **Description**: ${driver.Description}\n`;
      output += `- **Manufacturer**: ${driver.Manufacturer}\n`;
      output += `- **Device Class**: ${driver.DeviceClass}\n`;
      output += `- **Path**: ${driver.DriverPathName}\n`;
      if (driver.SecurityIssues && driver.SecurityIssues.length > 0) {
        output += `- **Security Issues**: ${driver.SecurityIssues.join(', ')}\n`;
      }
      output += `\n`;
    });
  }

  // Health Analysis section
  if (args.checkHealth && result.HealthAnalysis.ErrorDevices.length > 0) {
    output += `## Health Analysis\n\n`;
    output += `### Devices with Errors (${result.HealthAnalysis.ErrorDevices.length})\n\n`;
    
    result.HealthAnalysis.ErrorDevices.forEach((driver, index) => {
      output += `**${index + 1}. ${driver.DriverName}**\n`;
      output += `- **Description**: ${driver.Description}\n`;
      output += `- **Manufacturer**: ${driver.Manufacturer}\n`;
      output += `- **Device Class**: ${driver.DeviceClass}\n`;
      if (driver.HealthIssues && driver.HealthIssues.length > 0) {
        output += `- **Health Issues**: ${driver.HealthIssues.join(', ')}\n`;
      }
      output += `\n`;
    });
  }

  // Version Analysis section
  if (args.checkVersions && result.HealthAnalysis.OutdatedDrivers.length > 0) {
    output += `## Version Analysis\n\n`;
    output += `### Outdated Drivers (${result.HealthAnalysis.OutdatedDrivers.length})\n\n`;
    
    result.HealthAnalysis.OutdatedDrivers.forEach((driver, index) => {
      output += `**${index + 1}. ${driver.DriverName}**\n`;
      output += `- **Description**: ${driver.Description}\n`;
      output += `- **Manufacturer**: ${driver.Manufacturer}\n`;
      output += `- **Version**: ${driver.DriverVersion}\n`;
      output += `- **Date**: ${driver.DriverDate}\n`;
      if (driver.VersionIssues && driver.VersionIssues.length > 0) {
        output += `- **Version Issues**: ${driver.VersionIssues.join(', ')}\n`;
      }
      output += `\n`;
    });
  }

  // Driver Details section
  if (result.Drivers.length > 0) {
    output += `## Driver Details\n\n`;
    
    // Create a table for better readability
    output += `| Driver Name | Description | Device Class | Manufacturer | Version | Signed | Enabled |\n`;
    output += `|-------------|-------------|--------------|--------------|---------|--------|----------|\n`;
    
    result.Drivers.forEach(driver => {
      const signedStatus = driver.IsSigned ? '✅' : '❌';
      const enabledStatus = driver.IsEnabled ? '✅' : '❌';
      output += `| ${driver.DriverName} | ${driver.Description} | ${driver.DeviceClass} | ${driver.Manufacturer} | ${driver.DriverVersion} | ${signedStatus} | ${enabledStatus} |\n`;
    });
    
    output += `\n`;
  }

  // Errors section
  if (result.Errors.length > 0) {
    output += `## Errors\n\n`;
    result.Errors.forEach(error => {
      output += `- ❌ ${error}\n`;
    });
    output += `\n`;
  }

  // Additional details for specific drivers if detailed mode is enabled
  if (args.detailed && result.Drivers.length > 0) {
    output += `## Detailed Driver Information\n\n`;
    
    result.Drivers.slice(0, 5).forEach((driver, index) => { // Show details for first 5 drivers
      output += `### ${index + 1}. ${driver.DriverName}\n\n`;
      output += `- **Hardware ID**: ${driver.HardwareID}\n`;
      output += `- **Compatible ID**: ${driver.CompatID}\n`;
      output += `- **Device ID**: ${driver.DeviceID}\n`;
      output += `- **Signer**: ${driver.Signer}\n`;
      output += `- **Provider**: ${driver.ProviderName}\n`;
      output += `- **INF Name**: ${driver.InfName}\n`;
      output += `- **INF Section**: ${driver.InfSection}\n`;
      
      if (driver.DriverType !== undefined) {
        output += `- **Driver Type**: ${driver.DriverType}\n`;
      }
      if (driver.DriverRank !== undefined) {
        output += `- **Driver Rank**: ${driver.DriverRank}\n`;
      }
      
      output += `\n`;
    });
    
    if (result.Drivers.length > 5) {
      output += `*... and ${result.Drivers.length - 5} more drivers*\n\n`;
    }
  }

  return {
    content: [{ type: 'text', text: output }],
  };
}
