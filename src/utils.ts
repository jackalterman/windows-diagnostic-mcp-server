import { spawn } from "child_process";

export async function runPowerShellScript(
  script: string,
  params: { [key: string]: string | number | boolean | string[] | undefined } = {}
): Promise<any> {
  return new Promise((resolve, reject) => {
    const psArgs = ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"];

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

    // Use & operator to execute the script block with parameters
    const fullCommand = `& { ${script} } ${paramStrings.join(" ")}`;
    psArgs.push(fullCommand);

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