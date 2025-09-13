import { runPowerShellScript } from '../utils.js'
import * as AllTypes from '../types.js'
import * as fs from 'fs'
import * as path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const SCRIPT_PATH = path.resolve(__dirname, '../powershell_scripts/wmi_query.ps1')
const SCRIPT_CONTENT = fs.readFileSync(SCRIPT_PATH, 'utf-8')

/**
 * Securely query WMI (Windows Management Instrumentation) with comprehensive security controls
 * 
 * Security Features:
 * - Whitelist of approved WMI classes only (read-only system information)
 * - Input validation and sanitization
 * - Query timeout protection (default 30 seconds)
 * - Maximum result limits (1000 items max)
 * - Forbidden pattern detection in WHERE clauses
 * - No execution of arbitrary code or dangerous operations
 * 
 * @param args - WMI query parameters
 * @returns MCP-formatted response with query results and security information
 */
export async function wmiQuery(args: AllTypes.WmiQueryParams) {
  try {
    // Validate required parameters
    if (!args.className || args.className.trim() === '') {
      return {
        content: [{
          type: 'text',
          text: '❌ **Error**: ClassName is required for WMI queries.\n\n**Security Note**: Only approved WMI classes are allowed for security reasons.'
        }]
      }
    }

    // Set defaults
    const maxResults = Math.min(args.maxResults || 100, 1000) // Security: Cap at 1000
    const timeoutSeconds = Math.min(args.timeoutSeconds || 30, 60) // Security: Cap at 60 seconds

    const result = await runPowerShellScript(
      SCRIPT_CONTENT,
      {
        ClassName: args.className.trim(),
        Properties: args.properties ? args.properties.join(',') : '',
        WhereClause: args.whereClause || '',
        MaxResults: maxResults,
        TimeoutSeconds: timeoutSeconds,
        JsonOutput: true
      }
    ) as AllTypes.WmiQueryOutput

    // Format response based on success/failure
    if (!result.Success) {
      let errorMessage = '❌ **WMI Query Failed**\n\n'
      
      if (result.Errors && result.Errors.length > 0) {
        errorMessage += '**Errors:**\n'
        result.Errors.forEach(error => {
          errorMessage += `- ${error}\n`
        })
      }

      if (result.SecurityInfo && !result.SecurityInfo.ClassApproved) {
        errorMessage += '\n**Security Notice**: The requested WMI class is not in the approved whitelist. Only read-only system information classes are allowed for security reasons.'
      }

      return {
        content: [{ type: 'text', text: errorMessage }]
      }
    }

    // Success response
    let response = `✅ **WMI Query Successful**\n\n`
    
    // Security status
    response += `## 🔒 Security Status\n`
    response += `- **Class Approved**: ${result.SecurityInfo?.ClassApproved ? '✅ Yes' : '❌ No'}\n`
    response += `- **Query Sanitized**: ${result.SecurityInfo?.QuerySanitized ? '✅ Yes' : '❌ No'}\n`
    response += `- **Timeout Applied**: ${result.SecurityInfo?.TimeoutApplied ? '✅ Yes' : '❌ No'}\n`
    response += `- **Read-Only Operation**: ✅ Yes\n`
    if (result.SecurityInfo?.SecuritySummary) {
        response += `- **Max Results Limited**: ${result.SecurityInfo.SecuritySummary.MaxResultsLimited ? '✅ Yes' : '❌ No'}\n\n`
    } else {
        response += `- **Max Results Limited**: ❌ No\n\n`
    }

    // Query information
    response += `## 📊 Query Information\n`
    response += `- **Class**: \`${result.QueryInfo.ClassName}\`\n`
    response += `- **Properties**: ${result.QueryInfo.Properties.length > 0 ? result.QueryInfo.Properties.join(', ') : 'All (*)'}\n`
    response += `- **WHERE Clause**: ${result.QueryInfo.WhereClause || 'None'}\n`
    response += `- **Max Results**: ${result.QueryInfo.MaxResults}\n`
    response += `- **Actual Results**: ${result.QueryInfo.ActualResults}\n`
    response += `- **Execution Time**: ${result.ExecutionTime.toFixed(2)} seconds\n\n`

    // Warnings
    if (result.Warnings && result.Warnings.length > 0) {
      response += `## ⚠️ Warnings\n`
      result.Warnings.forEach(warning => {
        response += `- ${warning}\n`
      })
      response += '\n'
    }

    // Data preview
    if (result.Data && result.Data.length > 0) {
      response += `## 📋 Data Results (${result.Data.length} items)\n\n`
      
      // Show first few items as examples
      const previewCount = Math.min(3, result.Data.length)
      for (let i = 0; i < previewCount; i++) {
        const item = result.Data[i]
        response += `### Item ${i + 1}\n`
        response += '```json\n'
        response += JSON.stringify(item, null, 2)
        response += '\n```\n\n'
      }

      if (result.Data.length > previewCount) {
        response += `*... and ${result.Data.length - previewCount} more items*\n\n`
      }

      // Summary of properties
      if (result.Data.length > 0) {
        const allProperties = new Set<string>()
        result.Data.forEach(item => {
          Object.keys(item).forEach(key => allProperties.add(key))
        })
        
        response += `## 📝 Available Properties\n`
        response += `Found ${allProperties.size} unique properties:\n`
        response += Array.from(allProperties).sort().join(', ') + '\n\n'
      }
    } else {
      response += `## 📋 Data Results\nNo data returned for the specified query.\n\n`
    }

    // Security recommendations
    response += `## 🛡️ Security Notes\n`
    response += `- This tool only allows read-only queries on approved WMI classes\n`
    response += `- All queries are subject to timeout and result limits\n`
    response += `- Dangerous operations and code execution are prevented\n`
    response += `- Query inputs are validated and sanitized\n`

    return {
      content: [{ type: 'text', text: response }]
    }

  } catch (error) {
    return {
      content: [{
        type: 'text',
        text: `❌ **WMI Query Error**\n\nAn unexpected error occurred while executing the WMI query:\n\n\`\`\`\n${error instanceof Error ? error.message : String(error)}\n\`\`\`\n\n**Security Note**: This tool maintains strict security controls and only allows read-only operations on approved WMI classes.`
      }]
    }
  }
}
