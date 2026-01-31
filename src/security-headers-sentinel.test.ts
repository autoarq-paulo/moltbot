import { describe, expect, it, vi } from "vitest";
import { startTelegramWebhook } from "./telegram/webhook.js";
import {
  ensureChromeExtensionRelayServer,
  stopChromeExtensionRelayServer,
} from "./browser/extension-relay.js";
import { loginChutes } from "./commands/chutes-oauth.js";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

// Mock grammy and bot to avoid real API calls
vi.mock("grammy", async (importOriginal) => {
  const actual = await importOriginal<typeof import("grammy")>();
  return {
    ...actual,
    webhookCallback: () => (_req: any, res: any) => {
      res.writeHead(200);
      res.end("ok");
    },
  };
});

vi.mock("./telegram/bot.js", () => ({
  createTelegramBot: () => ({
    api: {
      setWebhook: vi.fn().mockResolvedValue(true),
      setMyCommands: vi.fn().mockResolvedValue(true),
    },
    stop: vi.fn(),
  }),
}));

async function getFreePort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const port = (s.address() as AddressInfo).port;
      s.close(() => resolve(port));
    });
    s.on("error", reject);
  });
}

const SECURITY_HEADERS = [
  "X-Content-Type-Options",
  "X-Frame-Options",
  "X-XSS-Protection",
  "Referrer-Policy",
];

describe("Security Headers Sentinel", () => {
  it("Telegram Webhook server should have security headers", async () => {
    const port = await getFreePort();
    const { stop } = await startTelegramWebhook({
      token: "test-token",
      port,
      host: "127.0.0.1",
    });

    try {
      const res = await fetch(`http://127.0.0.1:${port}/healthz`);
      expect(res.status).toBe(200);
      for (const header of SECURITY_HEADERS) {
        expect(
          res.headers.get(header),
          `Header ${header} missing from Telegram Webhook`,
        ).toBeTruthy();
      }
    } finally {
      stop();
    }
  });

  it("Extension Relay server should have security headers", async () => {
    const port = await getFreePort();
    const cdpUrl = `http://127.0.0.1:${port}`;
    await ensureChromeExtensionRelayServer({ cdpUrl });

    try {
      const res = await fetch(cdpUrl);
      for (const header of SECURITY_HEADERS) {
        expect(
          res.headers.get(header),
          `Header ${header} missing from Extension Relay`,
        ).toBeTruthy();
      }
    } finally {
      await stopChromeExtensionRelayServer({ cdpUrl });
    }
  });

  it("Chutes OAuth callback server should have security headers", async () => {
    const port = await getFreePort();
    const redirectUri = `http://127.0.0.1:${port}/callback`;

    let headersChecked = false;

    await loginChutes({
      app: { clientId: "test", redirectUri, scopes: [] },
      onAuth: async () => {
        const res = await fetch(redirectUri);
        for (const header of SECURITY_HEADERS) {
          expect(
            res.headers.get(header),
            `Header ${header} missing from Chutes OAuth`,
          ).toBeTruthy();
        }
        headersChecked = true;
        // Send a fake callback to let loginChutes finish
        await fetch(`${redirectUri}?code=abc&state=state123`);
      },
      onPrompt: async () => "",
      createState: () => "state123",
      fetchFn: async (url) => {
        if (String(url).includes("token")) {
          return new Response(
            JSON.stringify({ access_token: "at", refresh_token: "rt", expires_in: 3600 }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        return new Response(JSON.stringify({ username: "user" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      },
    });

    expect(headersChecked, "Headers were not checked for Chutes OAuth").toBe(true);
  });
});
