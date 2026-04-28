import { vi, describe, it, expect, afterEach } from "vitest";
import BlaiseIapNodeProvider from "./blaiseIapNodeProvider.js";
import jwt from "jsonwebtoken";

vi.mock("./googleTokenProvider.js");
import getGoogleAuthToken from "./googleTokenProvider.js";

const mockedGetGoogleAuthToken = vi.mocked(getGoogleAuthToken);

function mockAuthToken(token: string) {
  mockedGetGoogleAuthToken.mockResolvedValueOnce(token);
}

afterEach(() => {
  vi.clearAllMocks();
  vi.resetAllMocks();
});

describe("BlaiseIapNodeProvider", () => {
  it("returns auth headers with a valid token", async () => {
    const uniqueToken = "Tolkien";

    mockAuthToken(uniqueToken);
    const googleAuthProvider = new BlaiseIapNodeProvider("EXAMPLE_CLIENT_ID");
    const authHeader = await googleAuthProvider.getAuthHeader();

    expect(authHeader).toEqual({ Authorization: `Bearer ${uniqueToken}` });
    expect(mockedGetGoogleAuthToken).toHaveBeenCalledWith("EXAMPLE_CLIENT_ID");
  });

  it("fetches a new token when the current token has expired or is within the 30-second buffer", async () => {
    const olderMockToken = jwt.sign({ foo: "bar", exp: Math.floor(Date.now() / 1000) + 20 }, "shh");

    mockAuthToken(olderMockToken);
    const googleAuthProvider = new BlaiseIapNodeProvider("EXAMPLE_CLIENT_ID");

    await googleAuthProvider.getAuthHeader();
    const updatedMockToken = "MockSecondaryTokenCalled";

    mockAuthToken(updatedMockToken);
    const authHeader = await googleAuthProvider.getAuthHeader();

    expect(authHeader).toEqual({ Authorization: `Bearer ${updatedMockToken}` });
    expect(mockedGetGoogleAuthToken).toHaveBeenCalledTimes(2);
  });

  it("returns the cached token if it has not expired", async () => {
    const olderMockToken = jwt.sign(
      { foo: "bar", exp: Math.floor(Date.now() / 1000) + 60 * 60 },
      "shh",
    );

    mockAuthToken(olderMockToken);
    const googleAuthProvider = new BlaiseIapNodeProvider("EXAMPLE_CLIENT_ID");

    await googleAuthProvider.getAuthHeader();
    const updatedMockToken = "MockSecondaryTokenCalled";

    mockAuthToken(updatedMockToken);
    const authHeader = await googleAuthProvider.getAuthHeader();

    expect(authHeader).toEqual({ Authorization: `Bearer ${olderMockToken}` });
    expect(mockedGetGoogleAuthToken).toHaveBeenCalledTimes(1);
  });

  it("fetches a new token when the cached token is invalid", async () => {
    mockAuthToken("%%%%%");
    const googleAuthProvider = new BlaiseIapNodeProvider("EXAMPLE_CLIENT_ID");

    await googleAuthProvider.getAuthHeader();
    const updatedMockToken = "MockSecondaryTokenCalled";

    mockAuthToken(updatedMockToken);
    const authHeader = await googleAuthProvider.getAuthHeader();

    expect(authHeader).toEqual({ Authorization: `Bearer ${updatedMockToken}` });
    expect(mockedGetGoogleAuthToken).toHaveBeenCalledTimes(2);
  });

  it("deduplicates concurrent token requests", async () => {
    const uniqueToken = "ConcurrentToken";

    mockedGetGoogleAuthToken.mockImplementationOnce(
      () => new Promise((resolve) => setTimeout(() => resolve(uniqueToken), 10)),
    );

    const googleAuthProvider = new BlaiseIapNodeProvider("EXAMPLE_CLIENT_ID");
    const [header1, header2] = await Promise.all([
      googleAuthProvider.getAuthHeader(),
      googleAuthProvider.getAuthHeader(),
    ]);

    expect(header1).toEqual({ Authorization: `Bearer ${uniqueToken}` });
    expect(header2).toEqual({ Authorization: `Bearer ${uniqueToken}` });

    expect(mockedGetGoogleAuthToken).toHaveBeenCalledTimes(1);
  });

  it("throws an error and recovers state when fetching the token fails", async () => {
    const errorMessage = "Network failure";

    mockedGetGoogleAuthToken.mockRejectedValueOnce(new Error(errorMessage));

    const googleAuthProvider = new BlaiseIapNodeProvider("EXAMPLE_CLIENT_ID");

    await expect(googleAuthProvider.getAuthHeader()).rejects.toThrow(errorMessage);

    const recoveryToken = "RecoveryToken";

    mockAuthToken(recoveryToken);

    const recoveryHeader = await googleAuthProvider.getAuthHeader();

    expect(recoveryHeader).toEqual({ Authorization: `Bearer ${recoveryToken}` });
    expect(mockedGetGoogleAuthToken).toHaveBeenCalledTimes(2);
  });
});
