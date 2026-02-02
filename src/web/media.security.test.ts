import path from "node:path";
import { describe, expect, it } from "vitest";
import { loadWebMedia } from "./media.js";

describe("web media security", () => {
  it("VULNERABILITY FIX: rejects arbitrary absolute local files", async () => {
    const targetFile = path.resolve("package.json");
    await expect(loadWebMedia(targetFile)).rejects.toThrow(
      /Security error: Only relative local paths are allowed/i,
    );
  });

  it("VULNERABILITY FIX: rejects arbitrary files via file:// protocol", async () => {
    const targetFile = path.resolve("package.json");
    const fileUrl = `file://${targetFile}`;
    await expect(loadWebMedia(fileUrl)).rejects.toThrow(
      /Security error: file:\/\/ protocol is not allowed/i,
    );
  });

  it("VULNERABILITY FIX: rejects path traversal", async () => {
    await expect(loadWebMedia("../package.json")).rejects.toThrow(
      /Security error: Only relative local paths are allowed/i,
    );
  });

  it("VULNERABILITY FIX: rejects tilde expansion", async () => {
    await expect(loadWebMedia("~/test.jpg")).rejects.toThrow(
      /Security error: Only relative local paths are allowed/i,
    );
  });
});
