import type { JwtPayload } from "jsonwebtoken";
import jwt from "jsonwebtoken";
import getGoogleAuthToken from "./googleTokenProvider.js";

export default class BlaiseIapNodeProvider {
  private token = "";
  private expirationTimestamp = 0;
  private fetchTokenPromise: Promise<string> | null = null;

  constructor(private readonly CLIENT_ID: string) {}

  async getAuthHeader(): Promise<{ Authorization: string }> {
    if (!this.isValidToken()) {
      await this.refreshToken();
    }

    return { Authorization: `Bearer ${this.token}` };
  }

  private async refreshToken(): Promise<void> {
    if (!this.fetchTokenPromise) {
      this.fetchTokenPromise = getGoogleAuthToken(this.CLIENT_ID)
        .then((newToken) => {
          this.token = newToken;

          const decodedToken = jwt.decode(newToken, { json: true }) as JwtPayload | null;

          this.expirationTimestamp = decodedToken?.exp || 0;

          return newToken;
        })
        .catch((error) => {
          this.token = "";
          this.expirationTimestamp = 0;
          throw error;
        })
        .finally(() => {
          this.fetchTokenPromise = null;
        });
    }

    await this.fetchTokenPromise;
  }

  private isValidToken(): boolean {
    if (this.token === "") {
      return false;
    }

    const currentTimeInSeconds = Math.floor(Date.now() / 1000);
    const bufferInSeconds = 30;

    return this.expirationTimestamp > currentTimeInSeconds + bufferInSeconds;
  }
}
