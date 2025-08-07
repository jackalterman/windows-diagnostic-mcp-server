# Guide to Adding New Tools to `windows-diagnostic-mcp-server`

This guide outlines the conventions and steps required to add a new diagnostic tool to the project. Following these steps will ensure the new tool integrates correctly with the existing Node.js server and TypeScript codebase.

---

## 1. PowerShell Scripts (`src/powershell_scripts/`)

These scripts are the core of the diagnostic tooling, responsible for interacting with the Windows OS to gather data.

*   **Location**: All PowerShell scripts must be placed in the `src/powershell_scripts/` directory.
*   **Naming**: Use `snake_case` for filenames (e.g., `get_installed_apps.ps1`).
*   **Purpose**: Each script should perform a single, specific diagnostic task.
*   **Parameters**:
    *   Define any input parameters at the top of the script within a `param()` block.
    *   This allows the Node.js backend to pass arguments to the script.
*   **Output**:
    *   The script's **only** output to the standard output stream (`stdout`) must be a **single JSON object**.
    *   Build a PowerShell object (e.g., `$Results = @{...}`) throughout the script to collect all data and any errors.
    *   The very last line of execution should be `return $Results | ConvertTo-Json -Depth 10`.
*   **`Write-Host` is Forbidden**: Scripts **must not** contain any `Write-Host` commands. These write to the information stream, not `stdout`, and will interfere with the JSON parsing in the Node.js layer. The commit history shows that this is the desired convention.
*   **Error Handling**: Wrap WMI calls and other potentially failing operations in `try...catch` blocks. Log any errors to an `Errors` array within your main `$Results` object.
*   **Documentation**: Include a comment-based help block at the top of the file, explaining the script's purpose (`.SYNOPSIS`, `.DESCRIPTION`).

---

## 2. TypeScript Tool Wrappers (`src/tools/`)

Each PowerShell script needs a corresponding TypeScript file that defines it as a "Tool" for the server.

*   **Location**: All tool wrappers must be in the `src/tools/` directory.
*   **Naming**: The filename must **exactly match** its corresponding PowerShell script, but with a `.ts` extension (e.g., `get_installed_apps.ts`).
*   **Structure**: Each tool file must:
    1.  Import `Tool`, `ToolOutput`, and any necessary types from `../types.ts`.
    2.  Import the `runPowershellScript` helper from `../utils/runPowershellScript.ts`.
    3.  Define the tool's input parameters using a Zod schema for validation. If there are no parameters, use `z.object({})`.
    4.  Export a `const` of type `Tool`. This object contains the tool's `name`, `description`, the Zod `schema`, and an `execute` function.
    5.  The `execute` function receives the validated parameters, calls `runPowershellScript` with the script name and parameters, and returns the parsed JSON output.

---

## 3. Shared Type Definitions (`src/types.ts`)

This is the central location for all shared TypeScript types, ensuring consistency across the application.

*   **Location**: `src/types.ts`.
*   **Purpose**: Contains core interfaces like `Tool` and `ToolOutput`, as well as types for the parameters and return data of each tool.
*   **When to Update**:
    *   When adding a new tool, define a TypeScript type for its Zod schema (e.g., `type GetInstalledAppsParams = z.infer<typeof getInstalledAppsParamsSchema>;`).
    *   Define a type for the structured data object that the PowerShell script returns. This gives you type safety when handling the result in the tool's `execute` function.

---

## 4. Main Server / Tool Aggregator (`src/index.ts`)

This file is the application's entry point. It gathers all the individual tools and makes them available.

*   **Location**: Assumed to be `src/index.ts` or a similar entry file like `server.ts`.
*   **Purpose**: Imports all tool definitions from the `src/tools/` directory and aggregates them into a single collection (e.g., an array or map).
*   **When to Update**: After creating a new tool file (e.g., `src/tools/new_tool.ts`), you must import it in `index.ts` and add it to the master list of tools.