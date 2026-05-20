import { describe, expect, it, vi } from "vitest";

import { IapProvider } from "./iapProvider.js";

function createTokenWithExpiration(expiresInSeconds: number): string {
  const encodedHeader = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" }), "utf8").toString(
    "base64url",
  );
  const encodedPayload = Buffer.from(
    JSON.stringify({ exp: Math.floor(Date.now() / 1000) + expiresInSeconds }),
    "utf8",
  ).toString("base64url");

  return `${encodedHeader}.${encodedPayload}.`;
}

function createTokenWithPayload(payload: unknown): string {
  const encodedHeader = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" }), "utf8").toString(
    "base64url",
  );
  const encodedPayload = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");

  return `${encodedHeader}.${encodedPayload}.`;
}

describe("IapProvider", () => {
  it("rejects an empty target audience", () => {
    expect(() => new IapProvider("   ")).toThrow("IAP target audience is required.");
  });

  it("returns auth headers with a valid token", async () => {
    const validToken = createTokenWithExpiration(60 * 60);
    const fetchToken = vi.fn().mockResolvedValueOnce(validToken);
    const iapProvider = new IapProvider("EXAMPLE_CLIENT_ID", fetchToken);
    const authHeader = await iapProvider.getAuthHeader();

    expect(authHeader).toEqual({ Authorization: `Bearer ${validToken}` });
    expect(fetchToken).toHaveBeenCalledWith("EXAMPLE_CLIENT_ID");
  });

  it("fetches a new token when the current token has expired or is within the 30-second buffer", async () => {
    const expiringToken = createTokenWithExpiration(20);
    const refreshedToken = createTokenWithExpiration(60 * 60);
    const fetchToken = vi
      .fn()
      .mockResolvedValueOnce(expiringToken)
      .mockResolvedValueOnce(refreshedToken);
    const iapProvider = new IapProvider("EXAMPLE_CLIENT_ID", fetchToken);

    await iapProvider.getAuthHeader();
    const authHeader = await iapProvider.getAuthHeader();

    expect(authHeader).toEqual({ Authorization: `Bearer ${refreshedToken}` });
    expect(fetchToken).toHaveBeenCalledTimes(2);
  });

  it("returns the cached token if it has not expired", async () => {
    const cachedToken = createTokenWithExpiration(60 * 60);
    const fetchToken = vi.fn().mockResolvedValue(cachedToken);
    const iapProvider = new IapProvider("EXAMPLE_CLIENT_ID", fetchToken);

    await iapProvider.getAuthHeader();
    const authHeader = await iapProvider.getAuthHeader();

    expect(authHeader).toEqual({ Authorization: `Bearer ${cachedToken}` });
    expect(fetchToken).toHaveBeenCalledTimes(1);
  });

  it("rejects a token whose payload is not a JSON object", async () => {
    const fetchToken = vi.fn().mockResolvedValueOnce(createTokenWithPayload(null));
    const iapProvider = new IapProvider("EXAMPLE_CLIENT_ID", fetchToken);

    await expect(iapProvider.getAuthHeader()).rejects.toThrow(
      "Failed to read Google ID token expiration.",
    );
  });

  it("rejects a token with a non-numeric exp claim", async () => {
    const fetchToken = vi
      .fn()
      .mockResolvedValueOnce(createTokenWithPayload({ exp: "not-a-number" }));
    const iapProvider = new IapProvider("EXAMPLE_CLIENT_ID", fetchToken);

    await expect(iapProvider.getAuthHeader()).rejects.toThrow(
      "Failed to read Google ID token expiration.",
    );
  });

  it("rejects a token with an unparseable payload", async () => {
    const encodedHeader = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" }), "utf8").toString(
      "base64url",
    );
    const encodedPayload = Buffer.from("{not valid json}", "utf8").toString("base64url");
    const invalidToken = `${encodedHeader}.${encodedPayload}.`;
    const fetchToken = vi.fn().mockResolvedValueOnce(invalidToken);
    const iapProvider = new IapProvider("EXAMPLE_CLIENT_ID", fetchToken);

    await expect(iapProvider.getAuthHeader()).rejects.toThrow(
      "Failed to read Google ID token expiration.",
    );
  });

  it("rejects malformed tokens and recovers on the next request", async () => {
    const recoveredToken = createTokenWithExpiration(60 * 60);
    const fetchToken = vi.fn().mockResolvedValueOnce("%%%%%").mockResolvedValueOnce(recoveredToken);
    const iapProvider = new IapProvider("EXAMPLE_CLIENT_ID", fetchToken);

    await expect(iapProvider.getAuthHeader()).rejects.toThrow(
      "Failed to read Google ID token expiration.",
    );

    const authHeader = await iapProvider.getAuthHeader();

    expect(authHeader).toEqual({ Authorization: `Bearer ${recoveredToken}` });
    expect(fetchToken).toHaveBeenCalledTimes(2);
  });

  it("deduplicates concurrent token requests", async () => {
    const validToken = createTokenWithExpiration(60 * 60);
    const fetchToken = vi
      .fn()
      .mockImplementationOnce(
        () => new Promise((resolve) => setTimeout(() => resolve(validToken), 10)),
      );
    const iapProvider = new IapProvider("EXAMPLE_CLIENT_ID", fetchToken);
    const [header1, header2] = await Promise.all([
      iapProvider.getAuthHeader(),
      iapProvider.getAuthHeader(),
    ]);

    expect(header1).toEqual({ Authorization: `Bearer ${validToken}` });
    expect(header2).toEqual({ Authorization: `Bearer ${validToken}` });
    expect(fetchToken).toHaveBeenCalledTimes(1);
  });

  it("throws an error and recovers state when fetching the token fails", async () => {
    const errorMessage = "Network failure";
    const recoveryToken = createTokenWithExpiration(60 * 60);
    const fetchToken = vi
      .fn()
      .mockRejectedValueOnce(new Error(errorMessage))
      .mockResolvedValueOnce(recoveryToken);
    const iapProvider = new IapProvider("EXAMPLE_CLIENT_ID", fetchToken);

    await expect(iapProvider.getAuthHeader()).rejects.toThrow(errorMessage);

    const recoveryHeader = await iapProvider.getAuthHeader();

    expect(recoveryHeader).toEqual({ Authorization: `Bearer ${recoveryToken}` });
    expect(fetchToken).toHaveBeenCalledTimes(2);
  });
});
