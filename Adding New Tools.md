# Guide to Adding New Tools to `windows-diagnostic-mcp-server`

This guide reflects how tools work in this repository today. It covers creating a PowerShell script, defining its JSON output, adding TypeScript types, writing a tool wrapper, and registering the tool in the MCP server.

---

## 1) PowerShell script (`src/powershell_scripts/`)

Scripts do the actual Windows work and must return a single JSON object on stdout when called by the server.

- **Location**: place new scripts in `src/powershell_scripts/`.
- **Naming**: use `snake_case` (e.g., `my_new_tool.ps1`).
- **Parameters**:
  - Define a `param(...)` block. Use `[switch]` for booleans so passing `-Flag` is enough.
  - If you need arrays, prefer accepting them as comma-separated strings and split them in-script. Example pattern used in `event_viewer.ps1`:
    - Param: `[string]$EventIDs = ""`
    - Convert: `$EventIDs = $EventIDs ? ($EventIDs.Split(',') | % { [int]$_.Trim() }) : @()`
  - Include a `[switch]$JsonOutput` parameter if you want the script to support both JSON and human console output. The TypeScript wrappers pass `JsonOutput: true`.
- **Output contract**:
  - Build a hashtable like `$Results = @{ ... }` and populate strongly shaped properties (arrays, nested objects).
  - End with JSON only on stdout. Typical patterns in this repo:
    - Always JSON: `$Results | ConvertTo-Json -Depth 10`
    - Or gated by switch: `if ($JsonOutput) { $Results | ConvertTo-Json -Depth 10 } else { <human-readable output> }`
  - Do not write other content to stdout when emitting JSON. If you want debug output, prefer `Write-Error` or add fields to `$Results` like `Errors`, `Warnings`, or `DebugInfo`.
- **Error handling**: wrap potentially failing operations with `try/catch` and add messages to `$Results.Errors` rather than throwing.
- **Doc comments**: include `.SYNOPSIS` / `.DESCRIPTION` at the top.

Minimal template:
```powershell
param(
    [switch]$JsonOutput,
    [string]$Items = ""  # "a,b,c"; split inside script if needed
)

$Results = @{
    Items = @()
    Errors = @()
}

try {
    $arr = if ($Items -and $Items.Trim() -ne "") { $Items.Split(',') | % { $_.Trim() } } else { @() }
    foreach ($i in $arr) { $Results.Items += @{ Name = $i } }
} catch {
    $Results.Errors += $_.Exception.Message
}

if ($JsonOutput) {
    $Results | ConvertTo-Json -Depth 10
} else {
    # optional console output for direct use
    $Results
}
```

---

## 2) Shared TypeScript types (`src/types.ts`)

Add interfaces that match your script’s JSON output and, optionally, an interface for the tool params.

- **Location**: `src/types.ts`.
- **Outputs**: create interfaces with exact property names/types you emit from PowerShell. See existing types like `DiagnosticResults`, `RegistryDiagnosticResults`, `HardwareMonitorOutput` for patterns.
- **Params**: define an interface if helpful (e.g., `export interface MyToolParams { foo?: string; }`). Arrays in wrappers are usually `string[]` then converted to comma-separated strings for PowerShell.

Example:
```ts
export interface MyToolItem { Name: string }
export interface MyToolOutput { Items: MyToolItem[]; Errors: string[] }
export interface MyToolParams { Items?: string[] }
```

---

## 3) TypeScript tool wrapper (`src/tools/`)

Wrappers read the `.ps1` content and invoke it via the shared runner `runPowerShellScript`. They return MCP-formatted content.

- **Location**: `src/tools/`.
- **Imports**:
  - `runPowerShellScript` from `../utils.js` (note the `.js` extension because the build emits JS).
  - `* as fs`, `* as path`, and `fileURLToPath` to resolve the script path.
  - Types from `../types.js` (again, `.js` at runtime).
- **Script loading**:
  - Use `const __dirname = path.dirname(fileURLToPath(import.meta.url));`
  - Resolve and `fs.readFileSync` the `.ps1` file to a string (current wrappers pass script content, not a file path).
- **Parameter mapping**:
  - Booleans: pass `true` to include a PowerShell switch; omit if `false`.
  - Arrays: pass a string array; the runner will join with commas into a single param (`'a,b,c'`). Ensure your script splits it.
  - Always include `JsonOutput: true` if your script supports it.
- **Return format**: return MCP response with `content: [{ type: 'text', text: markdownOrText }]`.

Minimal template:
```ts
import { runPowerShellScript } from '../utils.js'
import * as AllTypes from '../types.js'
import * as fs from 'fs'
import * as path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const SCRIPT_PATH = path.resolve(__dirname, '../powershell_scripts/my_new_tool.ps1')
const SCRIPT_CONTENT = fs.readFileSync(SCRIPT_PATH, 'utf-8')

export async function myNewTool(args: AllTypes.MyToolParams = {}) {
  const result = await runPowerShellScript(
    SCRIPT_CONTENT,
    {
      JsonOutput: true,
      Items: (args.Items ?? []).map(String), // becomes 'a,b,c'
    }
  ) as AllTypes.MyToolOutput

  return {
    content: [{ type: 'text', text: `Found ${result.Items.length} item(s)` }],
  }
}
```

---

## 4) Register the tool in the MCP server (`src/index.ts`)

Add the tool to the list and implement the handler case.

1. Import your wrapper function near the top:
```ts
import * as myTool from './tools/my_new_tool.js'
```

2. Add a new entry to the `tools` array in the ListTools handler with its `name`, `description`, and `inputSchema` (JSON Schema):
```ts
{
  name: 'my_new_tool',
  description: 'Describe what it does',
  inputSchema: {
    type: 'object',
    properties: {
      Items: { type: 'array', items: { type: 'string' } },
    },
  },
}
```

3. Add a case in the CallTool handler switch to route calls:
```ts
case 'my_new_tool':
  return await myTool.myNewTool(args as AllTypes.MyToolParams)
```

Use existing registrations (e.g., `hardware_monitor`, `event_viewer`, registry tools) as references for style.

## 5) Conventions used by the runner (`src/utils.ts`)

`runPowerShellScript(scriptContent, params, options?)` executes PowerShell and parses JSON from stdout.

- **Booleans**: `true` becomes `-Flag` (omitted if `false`).
- **Arrays**: joined into a single comma-separated string: `-Names 'a,b,c'`.
- **Strings/numbers**: quoted and escaped: `-Param 'value'`.
- **Script content vs file**: current tools pass content; file execution is supported with `{ useScriptFile: true }`.
- The process fails if PowerShell exits non-zero or stdout is not valid JSON.

---

## 6) Practical examples in this repo

- **Event Viewer** (`event_viewer.ps1` + `src/tools/event_viewer.ts`):
  - Arrays passed as comma-separated strings (`EventIDs`, `Sources`, `LogNames`).
  - Wrapper converts `number[]` to strings and sets `JsonOutput: true`.
  - Returns a rich markdown summary.

- **Diagnostics** (`diagnostic.ps1` + `src/tools/diagnostics.ts`):
  - Uses `[switch]$Detailed` and `[switch]$JsonOutput`.
  - Wrapper maps booleans and `daysBack` to `DaysBack`.

- **Registry** (`windows_registry.ps1` + `src/tools/registry.ts`):
  - Script supports many switches (e.g., `-ScanStartup`, `-FindOrphaned`).
  - Wrapper always passes `JsonOutput: true`.

- **Apps & Processes** (`apps_and_processes.ps1` + `src/tools/apps_and_processes.ts`):
  - Multiple operations in one script; wrapper selects behavior by passing the relevant params.

- **Hardware Monitor** (`hardware_monitor.ps1` + `src/tools/hardware_monitor.ts`):
  - All boolean checks default to true if not provided; wrapper can override.

---

## 7) Checklist for adding a new tool

- PowerShell script created in `src/powershell_scripts/` with:
  - `param(...)` using switches for booleans
  - `$Results` object, `Errors` array
  - Final `ConvertTo-Json -Depth 10` on stdout (or gated by `$JsonOutput`)
  - No extra stdout when producing JSON
- Types added to `src/types.ts` (outputs and optional params)
- Wrapper added in `src/tools/` that:
  - Loads `.ps1` content and calls `runPowerShellScript`
  - Maps inputs to PowerShell param names and sets `JsonOutput: true`
  - Returns MCP `content` with text/markdown
- Registration in `src/index.ts`:
  - Import wrapper, add tool entry to `ListTools`, add case in switch
- Build and test:
  - `npm run build`
  - Start the server with your MCP client and call the tool

---

## Notes on legacy and exceptions

- Some scripts (e.g., network diagnostics) currently output console text for direct use. When integrating with the server, ensure they support JSON output and that the wrapper passes `JsonOutput: true`.
- File/module naming usually matches the PowerShell script (`hardware_monitor.ps1` ↔ `hardware_monitor.ts`). There are a few exceptions (e.g., `windows_registry.ps1` ↔ `registry.ts`). Consistency is preferred but not required—just import correctly in `src/index.ts`.