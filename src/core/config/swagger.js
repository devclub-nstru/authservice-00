import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import env from "./config.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const openApiPath = path.resolve(__dirname, "../../docs/openapi.json");

const defaultSpec = {
  openapi: "3.0.3",
  info: {
    title: "Kael API",
    version: "1.0.0",
    description: "OpenAPI docs for Kael",
  },
  servers: [
    {
      url: `http://localhost:${env.PORT}`,
      description: "Local",
    },
  ],
  paths: {},
};

let swaggerSpec = defaultSpec;

try {
  const content = fs.readFileSync(openApiPath, "utf8");
  const parsed = JSON.parse(content);
  swaggerSpec = {
    ...parsed,
    servers: [
      {
        url: `http://localhost:${env.PORT}`,
        description: "Local",
      },
    ],
  };
} catch {
  swaggerSpec = defaultSpec;
}

export default swaggerSpec;
