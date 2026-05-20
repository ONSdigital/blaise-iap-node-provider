import { fetchGoogleIdToken } from "./googleTokenProvider.js";

const TOKEN_EXPIRATION_BUFFER_SECONDS = 30;

type AuthHeader = {
  Authorization: string;
};

function readTokenExpirationTimestamp(token: string): number | null {
  const [, payloadSegment] = token.split(".");

  if (!payloadSegment) {
    return null;
  }

  try {
    const parsedPayload: unknown = JSON.parse(
      Buffer.from(payloadSegment, "base64url").toString("utf8"),
    );

    if (typeof parsedPayload !== "object" || parsedPayload === null) {
      return null;
    }

    const { exp: expirationTimestamp } = parsedPayload as Record<string, unknown>;

    if (typeof expirationTimestamp !== "number" || !Number.isFinite(expirationTimestamp)) {
      return null;
    }

    return expirationTimestamp;
  } catch {
    return null;
  }
}

export class IapProvider {
  private token = "";
  private expirationTimestamp = 0;
  private inFlightTokenRefresh: Promise<void> | null = null;

  constructor(
    private readonly targetAudience: string,
    private readonly fetchToken = fetchGoogleIdToken,
  ) {
    if (targetAudience.trim() === "") {
      throw new Error("IAP target audience is required.");
    }
  }

  async getAuthHeader(): Promise<AuthHeader> {
    if (!this.hasUsableCachedToken()) {
      await this.refreshToken();
    }

    return { Authorization: `Bearer ${this.token}` };
  }

  private async refreshToken(): Promise<void> {
    if (!this.inFlightTokenRefresh) {
      this.inFlightTokenRefresh = this.fetchAndCacheToken().finally(() => {
        this.inFlightTokenRefresh = null;
      });
    }

    await this.inFlightTokenRefresh;
  }

  private async fetchAndCacheToken(): Promise<void> {
    try {
      const token = await this.fetchToken(this.targetAudience);
      const expirationTimestamp = readTokenExpirationTimestamp(token);

      if (expirationTimestamp === null) {
        throw new Error("Failed to read Google ID token expiration.");
      }

      this.token = token;
      this.expirationTimestamp = expirationTimestamp;
    } catch (error) {
      this.token = "";
      this.expirationTimestamp = 0;
      throw error;
    }
  }

  private hasUsableCachedToken(): boolean {
    if (this.token === "") {
      return false;
    }

    const currentTimeInSeconds = Math.floor(Date.now() / 1000);

    return this.expirationTimestamp > currentTimeInSeconds + TOKEN_EXPIRATION_BUFFER_SECONDS;
  }
}
