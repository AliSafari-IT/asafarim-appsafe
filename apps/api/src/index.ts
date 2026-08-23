import cors from "cors";
import express, { type NextFunction, type Request, type Response } from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { config } from "./config.js";
import {
  clearSessionCookie,
  hasValidSession,
  secretsMatch,
  setSessionCookie,
} from "./session.js";

export function createApp() {
  const app = express();

  app.disable("x-powered-by");

  if (config.trustProxy) {
    app.set("trust proxy", 1);
  }

  app.use(helmet());
  app.use(
    cors({
      credentials: true,
      methods: ["GET", "POST", "OPTIONS"],
      allowedHeaders: ["Content-Type"],
      origin(origin, callback) {
        if (!origin || config.webOrigins.includes(origin)) {
          callback(null, true);
          return;
        }

        callback(null, false);
      },
    })
  );
  app.use(express.json({ limit: "16kb" }));

  app.get("/health", (_request, response) => {
    response.json({ ok: true });
  });

  const verifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: "draft-8",
    legacyHeaders: false,
  });

  app.post("/api/gate/verify", verifyLimiter, (request, response) => {
    const code =
      typeof request.body?.code === "string" ? request.body.code : "";

    if (!secretsMatch(code, config.accessCode)) {
      response.status(401).json({ unlocked: false });
      return;
    }

    setSessionCookie(response);
    response.json({ unlocked: true });
  });

  app.get("/api/gate/status", (request, response) => {
    response.json({ unlocked: hasValidSession(request) });
  });

  app.post("/api/gate/lock", (_request, response) => {
    clearSessionCookie(response);
    response.json({ unlocked: false });
  });

  app.use((_request, response) => {
    response.status(404).json({ error: "Not found" });
  });

  app.use(
    (
      _error: unknown,
      _request: Request,
      response: Response,
      _next: NextFunction
    ) => {
      response.status(500).json({ error: "Internal server error" });
    }
  );

  return app;
}

const app = createApp();

app.listen(config.port, () => {
  console.log(`AppSafe API listening on port ${config.port}`);
});
