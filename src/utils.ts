import { spawn } from "child_process";
import path from "path";

/**
 * Run a PowerShell script with parameters
 * @param script - The script content or file path to execute
 * @param params - Parameters to pass to the script
 * @param options - Execution options
 * @param options.useScriptFile - If true, treats script as a file path and uses -File parameter. 
 *                                If false/undefined, treats script as content and uses -Command (default behavior)
 */
export async function runPowerShellScript(
  script: string,
  params: { [key: string]: string | number | boolean | string[] | undefined } = {},
  options: { useScriptFile?: boolean } = { useScriptFile: false }
): Promise<any> {
  return new Promise((resolve, reject) => {
    const psArgs = ["-NoProfile", "-ExecutionPolicy", "Bypass"];

    // Build parameter string for PowerShell script invocation
    const paramStrings: string[] = [];
    Object.entries(params).forEach(([key, value]) => {
      if (value === undefined || value === null) return;

      if (typeof value === "boolean") {
        if (value) {
          paramStrings.push(`-${key}`); // Just the switch name if true
        }
        // Don't add anything if false
      } else if (Array.isArray(value)) {
        const escapedValues = value.map((v) => String(v).replace(/'/g, "''")).join(",");
        paramStrings.push(`-${key} '${escapedValues}'`);
      } else {
        const escapedValue = String(value).replace(/'/g, "''");
        paramStrings.push(`-${key} '${escapedValue}'`);
      }
    });

    // Handle both script file and script content execution
    if (options.useScriptFile) {
      // For script files, use -File parameter with path relative to build folder
      const scriptPath = script.replace(/^src\//, "");
      psArgs.push("-File", scriptPath, ...paramStrings);
    } else {
      // For script content (legacy behavior), use -Command and wrap in a script block
      const fullCommand = `& { ${script} } ${paramStrings.join(" ")}`;
      psArgs.push("-Command", fullCommand);
    }

    const powershell = spawn("powershell.exe", psArgs, {
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
    });

    let stdout = "";
    let stderr = "";

    powershell.stdout.on("data", (data: Buffer) => {
      stdout += data.toString();
    });

    powershell.stderr.on("data", (data: Buffer) => {
      stderr += data.toString();
    });

    powershell.on("close", (code: number) => {
      if (code !== 0) {
        reject(new Error(`PowerShell script failed with code ${code}:\n${stderr}`));
      } else {
        try {
          const result = JSON.parse(stdout.trim());
          resolve(result);
        } catch (err) {
          reject(
            new Error(
              `Failed to parse JSON output: ${
                err instanceof Error ? err.message : String(err)
              }\nOutput:\n${stdout}`
            )
          );
        }
      }
    });

    powershell.on("error", (error: Error) => {
      reject(new Error(`Failed to start PowerShell: ${error.message}`));
    });
  });
}