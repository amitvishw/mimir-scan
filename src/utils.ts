import { spawn } from "child_process";

/** Run a command and return stdout/stderr */
export async function runCommand(
  cmd: string,
  args: string[],
  options?: { cwd?: string; timeout?: number; env?: Record<string, string> }
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    const proc = spawn(cmd, args, {
      cwd: options?.cwd,
      timeout: options?.timeout ?? 120_000,
      stdio: ["ignore", "pipe", "pipe"],
      env: options?.env ? { ...process.env, ...options.env } : undefined,
    });

    const chunks: Buffer[] = [];
    const errChunks: Buffer[] = [];

    proc.stdout.on("data", (data: Buffer) => chunks.push(data));
    proc.stderr.on("data", (data: Buffer) => errChunks.push(data));

    proc.on("error", (err) => {
      reject(new Error(`Failed to run ${cmd}: ${err.message}`));
    });

    proc.on("close", (code) => {
      resolve({
        stdout: Buffer.concat(chunks).toString("utf-8"),
        stderr: Buffer.concat(errChunks).toString("utf-8"),
        exitCode: code ?? 1,
      });
    });
  });
}

/** Check if a command exists on the system */
export async function commandExists(cmd: string): Promise<boolean> {
  try {
    const result = await runCommand("which", [cmd], { timeout: 5_000 });
    return result.exitCode === 0;
  } catch {
    return false;
  }
}

/** Generate a unique finding ID */
export function generateFindingId(
  scanner: string,
  filePath: string,
  line: number | undefined,
  rule: string
): string {
  const parts = [scanner, filePath, line ?? "0", rule];
  return parts.join(":").replace(/[^a-zA-Z0-9:._/-]/g, "_");
}

/** Get list of changed files from git diff */
export async function getGitChangedFiles(
  targetDir: string,
  base?: string
): Promise<{ files: string[]; error?: string }> {
  try {
    // Check if it's a git repository
    const gitCheck = await runCommand("git", ["rev-parse", "--git-dir"], {
      cwd: targetDir,
      timeout: 5_000,
    });

    if (gitCheck.exitCode !== 0) {
      return { files: [], error: "Not a git repository" };
    }

    // Get changed files
    const args = base ? ["diff", "--name-only", base, "HEAD"] : ["diff", "--name-only", "HEAD"];

    const result = await runCommand("git", args, {
      cwd: targetDir,
      timeout: 30_000,
    });

    // If no base comparison works, try getting staged + unstaged changes
    if (result.stdout.trim() === "" && !base) {
      const statusResult = await runCommand("git", ["status", "--porcelain"], {
        cwd: targetDir,
        timeout: 30_000,
      });

      const files = statusResult.stdout
        .split("\n")
        .filter((line) => line.trim())
        .map((line) => line.slice(3).trim())
        .filter((file) => file);

      return { files };
    }

    const files = result.stdout
      .split("\n")
      .map((f) => f.trim())
      .filter((f) => f);

    return { files };
  } catch (err) {
    return {
      files: [],
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
