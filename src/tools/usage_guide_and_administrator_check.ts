// src/tools/system_info.ts

import { runPowerShellScript } from '../utils.js'
import * as AllTypes from '../types.js'
import * as fs from 'fs'
import * as path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const SCRIPT_PATH = path.resolve(__dirname, '../powershell_scripts/usage_guide_and_administrator_check.ps1')
const SCRIPT_CONTENT = fs.readFileSync(SCRIPT_PATH, 'utf-8')

export async function getSystemInfo(args: AllTypes.SystemInfoParams = {}) {
  const result = await runPowerShellScript(
    SCRIPT_CONTENT,
    {
      JsonOutput: true,
      FixExecutionPolicy: args.FixExecutionPolicy,
      ShowHelp: args.ShowHelp,
      Detailed: args.Detailed,
    }
  ) as AllTypes.SystemInfoOutput

  // Build comprehensive markdown response
  let response = "# System Information & Diagnostic Setup\n\n"

  // Status Overview
  response += "## System Status\n\n"
  response += `**Administrator Privileges:** ${result.IsAdministrator ? '✅ ELEVATED' : '⚠️ LIMITED'}\n`
  response += `**Current User:** ${result.AdminDetails.CurrentUser}\n`
  response += `**PowerShell Scripts:** ${result.PowerShellInfo.CanRunScripts ? '✅ ENABLED' : '❌ RESTRICTED'}\n`
  response += `**Domain Status:** ${result.DomainInfo.IsPartOfDomain ? '🌐 Domain-joined' : '🏠 Workgroup'}\n`
  response += `**Ready for Full Diagnostics:** ${result.Summary.ReadyForDiagnostics ? '✅ YES' : '⚠️ PARTIAL'}\n\n`

  // Domain Information
  if (result.DomainInfo.IsPartOfDomain) {
    response += "## Domain Information\n\n"
    response += `**Domain:** ${result.DomainInfo.Domain}\n`
    response += `**Domain Role:** ${result.DomainInfo.DomainRole}\n`
    if (result.DomainInfo.Forest) {
      response += `**Forest:** ${result.DomainInfo.Forest}\n`
    }
    if (result.DomainInfo.DomainControllers && result.DomainInfo.DomainControllers.length > 0) {
      response += `**Domain Controllers:** ${result.DomainInfo.DomainControllers.join(', ')}\n`
    }
    response += `**Is Domain Controller:** ${result.DomainInfo.IsDomainController ? 'Yes' : 'No'}\n\n`
  } else {
    response += "## Network Configuration\n\n"
    response += `**Workgroup:** ${result.DomainInfo.Workgroup || 'Unknown'}\n\n`
  }

  // PowerShell Configuration
  response += "## PowerShell Configuration\n\n"
  response += `**Version:** ${result.PowerShellInfo.PSVersion} (${result.PowerShellInfo.PSEdition})\n`
  response += `**Execution Policy:** ${result.PowerShellInfo.EffectivePolicy}\n`
  response += `**Current User Policy:** ${result.PowerShellInfo.CurrentUserPolicy}\n`
  response += `**Local Machine Policy:** ${result.PowerShellInfo.LocalMachinePolicy}\n`
  
  if (result.PowerShellInfo.PolicyFixed) {
    response += `**✅ Policy Updated:** Set to ${result.PowerShellInfo.NewPolicy} for current user\n`
  }
  response += "\n"

  // System Information (if detailed)
  if (result.SystemInfo) {
    response += "## System Details\n\n"
    response += `**OS:** ${result.SystemInfo.OS}\n`
    response += `**Version:** ${result.SystemInfo.Version}\n`
    response += `**Build:** ${result.SystemInfo.Build}\n`
    response += `**RAM:** ${result.SystemInfo.TotalRAM_GB} GB\n`
    response += `**Architecture:** ${result.SystemInfo.Architecture}\n`
    response += `**Logical Processors:** ${result.SystemInfo.LogicalProcessors}\n\n`
  }

  // Recommendations
  if (result.Recommendations.length > 0) {
    response += "## Recommendations\n\n"
    for (const rec of result.Recommendations) {
      response += `- ${rec}\n`
    }
    response += "\n"
  }

  // Usage Guide
  if (result.UsageGuide && Object.keys(result.UsageGuide).length > 0) {
    response += "## Diagnostic Toolset Usage Guide\n\n"
    
    response += "### 🚀 Quick Start\n\n"
    response += `**Basic Health Check:** \`get_system_diagnostics\`\n`
    response += `**Hardware Monitor:** \`hardware_monitor\`\n`
    response += `**Event Analysis:** \`event_viewer\` with search terms\n`
    response += `**Deep Analysis:** \`analyze_system_stability\` with 30+ days\n\n`

    response += "### 🔍 Common Troubleshooting Workflows\n\n"
    
    response += "**System Crashes:**\n"
    if (result.UsageGuide.CommonWorkflows?.TroubleshootCrashes) {
      for (const step of result.UsageGuide.CommonWorkflows.TroubleshootCrashes) {
        response += `- ${step}\n`
      }
    }
    response += "\n"
    
    response += "**Performance Issues:**\n"
    if (result.UsageGuide.CommonWorkflows?.PerformanceAnalysis) {
      for (const step of result.UsageGuide.CommonWorkflows.PerformanceAnalysis) {
        response += `- ${step}\n`
      }
    }
    response += "\n"
    
    response += "**Security Audit:**\n"
    if (result.UsageGuide.CommonWorkflows?.SecurityAudit) {
      for (const step of result.UsageGuide.CommonWorkflows.SecurityAudit) {
        response += `- ${step}\n`
      }
    }
    response += "\n"
    
    response += "**Storage Management:**\n"
    if (result.UsageGuide.CommonWorkflows?.StorageManagement) {
      for (const step of result.UsageGuide.CommonWorkflows.StorageManagement) {
        response += `- ${step}\n`
      }
    }
    response += "\n"

    response += "### 📚 Available Tool Categories\n\n"
    const categories = result.UsageGuide.ToolCategories
    if (categories) {
      response += `**System Health:** ${categories.SystemHealth?.join(', ')}\n`
      response += `**Hardware:** ${categories.Hardware?.join(', ')}\n`
      response += `**Storage:** ${categories.Storage?.join(', ')}\n`
      response += `**Events:** ${categories.Events?.join(', ')}\n`
      response += `**Registry:** ${categories.Registry?.join(', ')}\n`
      response += `**Processes:** ${categories.Processes?.join(', ')}\n`
      response += `**Startup:** ${categories.Startup?.join(', ')}\n\n`
    }

    response += "### 🔐 Permission Requirements\n\n"
    if (result.UsageGuide.PermissionNotes) {
      response += `**Note:** ${result.UsageGuide.PermissionNotes.RequiredForMost}\n\n`
      response += `**Can Run Without Admin:** ${result.UsageGuide.PermissionNotes.CanRunWithoutAdmin?.join(', ')}\n\n`
      response += `**Admin Recommended:** ${result.UsageGuide.PermissionNotes.AdminRecommended?.join(', ')}\n\n`
      
      if (result.UsageGuide.PermissionNotes.PerformanceNotes) {
        response += "### ⚡ Performance Notes\n\n"
        for (const note of result.UsageGuide.PermissionNotes.PerformanceNotes) {
          response += `${note}\n`
        }
        response += "\n"
      }
    }
  }

  // Errors and Warnings
  if (result.Errors.length > 0) {
    response += "## ❌ Errors\n\n"
    for (const error of result.Errors) {
      response += `- ${error}\n`
    }
    response += "\n"
  }

  if (result.Warnings.length > 0) {
    response += "## ⚠️ Warnings\n\n"
    for (const warning of result.Warnings) {
      response += `- ${warning}\n`
    }
    response += "\n"
  }

  // Next Steps
  response += "## Next Steps\n\n"
  if (result.Summary.ReadyForDiagnostics) {
    response += "✅ **System is ready for full diagnostic operations.**\n\n"
    response += "**Recommended starting points:**\n"
    response += "- Run `get_system_diagnostics` for an overview\n"
    response += "- Use `hardware_monitor` to check system health\n"
    response += "- Try `event_viewer` to analyze recent events\n"
  } else {
    response += "⚠️ **System has limitations for diagnostic operations.**\n\n"
    response += "**To enable full functionality:**\n"
    if (!result.IsAdministrator) {
      response += "- Run this tool as Administrator for elevated privileges\n"
    }
    if (!result.PowerShellInfo.CanRunScripts) {
      response += "- Use `FixExecutionPolicy: true` parameter to enable script execution\n"
    }
    response += "\n**Tools that work with current permissions:**\n"
    response += "- `list_processes`, `list_installed_apps`, `get_system_uptime`\n"
    response += "- Basic `hardware_monitor` (limited sensors)\n"
  }

  return {
    content: [{ type: 'text', text: response }],
  }
}