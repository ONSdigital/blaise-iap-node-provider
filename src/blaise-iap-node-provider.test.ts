import { vi, describe, it, expect, afterEach } from "vitest";
import BlaiseIapNodeProvider from "./blaise-iap-node-provider.js";
import jwt from "jsonwebtoken";

vi.mock("./google-token-provider");
import getGoogleAuthToken from "./google-token-provider";

const mockedGetGoogleAuthToken = vi.mocked(getGoogleAuthToken);

function mockAuthToken(token: string) {
  mockedGetGoogleAuthToken.mockResolvedValueOnce(token);
}

afterEach(() => {
  vi.clearAllMocks();
  vi.resetAllMocks();
});

describe("BlaiseIapNodeProvider", () => {
  it("We can get back auth headers with a token", async () => {
    const uniqueToken = "Tolkien";

    mockAuthToken(uniqueToken);
    const googleAuthProvider = new BlaiseIapNodeProvider("EXAMPLE_CLIENT_ID");
    const authHeader = await googleAuthProvider.getAuthHeader();

    expect(authHeader).toEqual({ Authorization: `Bearer ${uniqueToken}` });
    expect(mockedGetGoogleAuthToken).toHaveBeenCalledWith("EXAMPLE_CLIENT_ID");
  });

  it("We get a new token when a token has expired or is within the 30-second buffer", async () => {
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

  it("We receive the same token if it hasn't expired", async () => {
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

  it("We get a new token when a token is invalid", async () => {
    mockAuthToken("%%%%%");
    const googleAuthProvider = new BlaiseIapNodeProvider("EXAMPLE_CLIENT_ID");

    await googleAuthProvider.getAuthHeader();
    const updatedMockToken = "MockSecondaryTokenCalled";

    mockAuthToken(updatedMockToken);
    const authHeader = await googleAuthProvider.getAuthHeader();

    expect(authHeader).toEqual({ Authorization: `Bearer ${updatedMockToken}` });
    expect(mockedGetGoogleAuthToken).toHaveBeenCalledTimes(2);
  });
});
