import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import swaggerJsdoc from "swagger-jsdoc";
import { OPENAPI_COMPONENTS } from "../docs/openapi/openapi.components.js";
import { OPENAPI_TAGS } from "../docs/openapi/openapi.constants.js";
import { OPENAPI_PATH_DEFINITIONS } from "../docs/openapi/openapi.paths.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "../..");
const outputPath = path.join(projectRoot, "src/docs/openapi.json");

const options = {
  definition: {
    openapi: "3.0.3",
    info: {
      title: "Kael API",
      version: "1.0.0",
      description: "OpenAPI docs for Kael",
    },
    servers: [
      {
        url: "http://localhost:3000",
        description: "Local",
      },
    ],
  },
  apis: [path.join(projectRoot, "index.js")],
};

const baseSpec = swaggerJsdoc(options);

const spec = {
  ...baseSpec,
  tags: [
    {
      name: OPENAPI_TAGS.AUTH,
      description: "Authentication and session management",
    },
    { name: OPENAPI_TAGS.USERS, description: "User profile operations" },
    {
      name: OPENAPI_TAGS.ORGANIZATIONS,
      description: "Organization management, members, and invites",
    },
    {
      name: OPENAPI_TAGS.CLIENTS,
      description: "Organization OAuth client and provider configuration",
    },
    { name: OPENAPI_TAGS.OAUTH, description: "OAuth provider integrations" },
  ],
  components: {
    ...(baseSpec.components || {}),
    securitySchemes: {
      ...((baseSpec.components && baseSpec.components.securitySchemes) || {}),
      ...OPENAPI_COMPONENTS.securitySchemes,
    },
    schemas: {
      ...((baseSpec.components && baseSpec.components.schemas) || {}),
      ...OPENAPI_COMPONENTS.schemas,
    },
  },
  paths: {
    ...(baseSpec.paths || {}),
    ...OPENAPI_PATH_DEFINITIONS,
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(spec, null, 2)}\n`, "utf8");

console.log(`OpenAPI spec generated at ${outputPath}`);
