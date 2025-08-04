import { spawn } from "child_process";
export async function runPowerShellScript(
  script: string,
  params: { [key: string]: string | number | boolean | undefined } = {}
): Promise<any> {
  return new Promise((resolve, reject) => {
    const psArgs = ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"];
    const paramStrings: string[] = [];
    Object.entries(params).forEach(([key, value]) => {
      if (value === undefined || value === null) {
        return;
      }
      if (typeof value === "boolean") {
        if (value) {
          paramStrings.push(`-${key}`);
        }
      } else {
        const escapedValue = String(value).replace(/'/g, "''");
        paramStrings.push(`-${key} '${escapedValue}'`);
      }
    });

    const fullScript = `& { ${script} } ${paramStrings.join(" ")}`;
    psArgs.push(fullScript);
    const powershell = spawn("powershell.exe", psArgs, {
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
    });
    let stdout = "";
    let stderr = "";
    powershell.stdout.on("data", (data) => {
      stdout += data.toString();
    });
    powershell.stderr.on("data", (data) => {
      stderr += data.toString();
    });
    powershell.on("close", (code) => {
      if (code !== 0) {
        reject(
          new Error(`PowerShell script failed with code ${code}: ${stderr}`)
        );
      } else {
        try {
          const result = JSON.parse(stdout);
          resolve(result);
        } catch (parseError) {
          reject(
            new Error(`Failed to parse JSON output: ${
              parseError instanceof Error
                ? parseError.message
                : String(parseError)
            }
Output: ${stdout}`)
          );
        }
      }
    });
    powershell.on("error", (error) => {
      reject(new Error(`Failed to start PowerShell: ${error.message}`));
    });
  });
}
