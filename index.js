import express from "express";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import cors from "cors";
import env from "./src/core/config/config.js";
import swaggerUi from "swagger-ui-express";
import swaggerSpec from "./src/core/config/swagger.js";
import requestContext from "./src/utils/request-context.js";
import errorMiddleware from "./src/utils/error-middleware.js";
import authRoutes from "./src/modules/auth/auth.routes.js";
import userRoutes from "./src/modules/user/user.routes.js";
import oauthRoutes from "./src/modules/oauth/oauth.routes.js";
import {
  closeRedisConnection,
  ensureRedisConnection,
} from "./src/core/config/redis.js";
import { cleanupQueue } from "./src/queues/index.js";
import logger from "./src/core/logger/logger.js";
import {
  CLEANUP_SCHEDULE,
  QUEUE_JOB_NAMES,
} from "./src/core/constants/queue.constants.js";

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(requestContext);
app.use(morgan("dev"));
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  }),
);

app.use(
  cors({
    origin: env.FRONTEND_URL,
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

app.use(
  "/api-docs",
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpec, { explorer: true }),
);

app.get("/api-docs.json", (req, res) => {
  res.status(200).json(swaggerSpec);
});

app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/oauth", oauthRoutes);

/**
 * @openapi
 * /health:
 *   get:
 *     summary: Service health check
 *     tags:
 *       - Health
 *     responses:
 *       200:
 *         description: Service is healthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: ok
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                 uptime:
 *                   type: number
 */
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

app.use(errorMiddleware);

const bootstrap = async () => {
  await ensureRedisConnection();

  await cleanupQueue.add(
    QUEUE_JOB_NAMES.CLEANUP_EXPIRED_RECORDS,
    {},
    {
      repeat: { every: CLEANUP_SCHEDULE.intervalMs },
      jobId: CLEANUP_SCHEDULE.jobId,
    },
  );

  const server = app.listen(env.PORT, () => {
    logger.info("Server listening", { port: env.PORT });
  });

  const shutdown = async () => {
    logger.info("Server shutdown started");

    server.close(async () => {
      await closeRedisConnection();
      logger.info("Server shutdown complete");
      process.exit(0);
    });
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
};

bootstrap().catch(async (error) => {
  logger.error("Server bootstrap failed", {
    error: error.message,
    stack: error.stack,
  });

  await closeRedisConnection();
  process.exit(1);
});
