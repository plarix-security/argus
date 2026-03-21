/**
 * AFB Scanner - GitHub App Entry Point
 *
 * Express server that handles GitHub App webhooks for push and pull_request events.
 * Triggers AFB04 analysis and reports findings as PR comments.
 */

import express, { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import {
  handlePullRequest,
  handlePush,
  parseWebhookPayload,
  GitHubAppConfig,
} from "./github/webhook-handler";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

/** Application configuration from environment */
const config: GitHubAppConfig = {
  appId: process.env.GITHUB_APP_ID || "",
  privateKey: (process.env.GITHUB_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
  webhookSecret: process.env.GITHUB_WEBHOOK_SECRET,
};

/** Express application */
const app = express();

/** Port to listen on */
const PORT = process.env.PORT || 3000;

/**
 * Verify GitHub webhook signature.
 */
function verifyWebhookSignature(
  payload: string,
  signature: string | undefined,
  secret: string | undefined
): boolean {
  if (!secret || !signature) {
    // If no secret configured, skip verification (not recommended for production)
    return !secret;
  }

  const expectedSignature = `sha256=${crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("hex")}`;

  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

// Parse raw body for signature verification
app.use(
  express.json({
    verify: (req: Request, _res: Response, buf: Buffer) => {
      (req as Request & { rawBody: string }).rawBody = buf.toString();
    },
  })
);

/**
 * Health check endpoint.
 */
app.get("/health", (_req: Request, res: Response) => {
  res.json({
    status: "healthy",
    service: "afb-scanner",
    version: "1.0.0",
  });
});

/**
 * GitHub webhook endpoint.
 */
app.post("/webhook", async (req: Request, res: Response, next: NextFunction) => {
  try {
    const event = req.headers["x-github-event"] as string;
    const signature = req.headers["x-hub-signature-256"] as string | undefined;
    const rawBody = (req as Request & { rawBody: string }).rawBody;

    // Verify signature
    if (!verifyWebhookSignature(rawBody, signature, config.webhookSecret)) {
      console.error("[AFB Scanner] Invalid webhook signature");
      res.status(401).json({ error: "Invalid signature" });
      return;
    }

    // Parse payload
    const context = parseWebhookPayload(event, req.body);

    if (!context) {
      // Not an event we handle
      res.json({ status: "ignored", event });
      return;
    }

    // Check if we should process this event
    if (event === "pull_request") {
      const action = req.body.action;
      if (!["opened", "synchronize", "reopened"].includes(action)) {
        res.json({ status: "ignored", event, action });
        return;
      }
    }

    // Acknowledge webhook immediately
    res.json({ status: "processing", event });

    // Process asynchronously
    console.log(`[AFB Scanner] Processing ${event} webhook`);

    if (event === "pull_request") {
      handlePullRequest(config, context).catch((error) => {
        console.error("[AFB Scanner] Error processing pull_request:", error);
      });
    } else if (event === "push") {
      handlePush(config, context).catch((error) => {
        console.error("[AFB Scanner] Error processing push:", error);
      });
    }
  } catch (error) {
    next(error);
  }
});

/**
 * Error handler.
 */
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error("[AFB Scanner] Error:", err);
  res.status(500).json({
    error: "Internal server error",
    message: err.message,
  });
});

/**
 * Start the server.
 */
function startServer(): void {
  // Validate configuration
  if (!config.appId) {
    console.error("[AFB Scanner] GITHUB_APP_ID is required");
    process.exit(1);
  }

  if (!config.privateKey) {
    console.error("[AFB Scanner] GITHUB_PRIVATE_KEY is required");
    process.exit(1);
  }

  app.listen(PORT, () => {
    console.log(`[AFB Scanner] Server running on port ${PORT}`);
    console.log(`[AFB Scanner] Webhook endpoint: http://localhost:${PORT}/webhook`);
    console.log(`[AFB Scanner] Health check: http://localhost:${PORT}/health`);
  });
}

// Start if run directly
if (require.main === module) {
  startServer();
}

export { app, startServer };
