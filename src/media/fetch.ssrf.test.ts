import { describe, expect, it } from "vitest";
import { fetchRemoteMedia } from "./fetch.js";

describe("fetchRemoteMedia SSRF protection", () => {
  it("rejects localhost", async () => {
    await expect(fetchRemoteMedia({ url: "http://localhost/media.jpg" })).rejects.toThrow(
      /Blocked hostname: localhost/i,
    );
  });

  it("rejects private IPs", async () => {
    await expect(fetchRemoteMedia({ url: "http://127.0.0.1/media.jpg" })).rejects.toThrow(
      /Blocked: private\/internal IP address/i,
    );
  });
});
