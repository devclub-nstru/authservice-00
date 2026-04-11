import { spawn } from "node:child_process";

const shell = process.platform === "win32";

const startProcess = (args) => {
  const child = spawn("npm", args, {
    stdio: "inherit",
    shell,
  });

  child.on("error", (error) => {
    console.error(`[dev:all] Failed to start npm ${args.join(" ")}:`, error);
  });

  return child;
};

const api = startProcess(["run", "dev"]);
const worker = startProcess(["run", "worker"]);

let shuttingDown = false;

const shutdown = (signal) => {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;

  api.kill(signal);
  worker.kill(signal);
  process.exit(0);
};

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

api.on("exit", (code) => {
  if (!shuttingDown) {
    worker.kill("SIGTERM");
    process.exit(code ?? 1);
  }
});

worker.on("exit", (code) => {
  if (!shuttingDown) {
    api.kill("SIGTERM");
    process.exit(code ?? 1);
  }
});
