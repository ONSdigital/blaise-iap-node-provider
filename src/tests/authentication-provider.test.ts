import BlaiseIapNodeProvider from "../blaise-iap-node-provider";
import jwt from "jsonwebtoken";

jest.mock("../authentication/google-token-provider");
import getGoogleAuthToken from "../authentication/google-token-provider";

const mockedGetGoogleAuthToken = getGoogleAuthToken as jest.Mock<Promise<string>>;

function mockAuthToken(token: string) {
    mockedGetGoogleAuthToken.mockImplementationOnce(() => {
        return Promise.resolve(token);
    });
}

afterEach(() => {
    mockedGetGoogleAuthToken.mockClear();
    jest.clearAllMocks();
    jest.resetAllMocks();
});

it("We can get back Auth headers with a token", async () => {
    const uniqueToken = "A Token";
    mockAuthToken(uniqueToken);
    const googleAuthProvider = new BlaiseIapNodeProvider("EXAMPLE_CLIENT_ID");

    const authHeader = await googleAuthProvider.getAuthHeader();

    expect(authHeader).toEqual({Authorization: `Bearer ${uniqueToken}`});
    expect(mockedGetGoogleAuthToken).toBeCalledWith("EXAMPLE_CLIENT_ID");
});


it("We get a new token when a token has expired", async () => {
    console.log = jest.fn();
    // Setup old token for 30 seconds in the past
    const olderMockToken = jwt.sign({foo: "bar", exp: Math.floor(Date.now() / 1000) - 30}, "shhhhh");
    mockAuthToken(olderMockToken);
    const googleAuthProvider = new BlaiseIapNodeProvider("EXAMPLE_CLIENT_ID");
    await googleAuthProvider.getAuthHeader();

    // Call for header with should have expired now
    const updatedMockToken = "MockSecondaryTokenCalled";
    mockAuthToken(updatedMockToken);

    const authHeader = await googleAuthProvider.getAuthHeader();

    expect(authHeader).toEqual({Authorization: `Bearer ${updatedMockToken}`});
    expect(console.log).toHaveBeenCalledWith("Auth Token Expired, Calling for new Google auth Token");
});


it("We receive the same token if it hasn't expired", async () => {
    console.log = jest.fn();
    // Setup token for an hour in the future
    const olderMockToken = jwt.sign({foo: "bar", exp: Math.floor(Date.now() / 1000) + (60 * 60)}, "shhhhh");
    mockAuthToken(olderMockToken);
    const googleAuthProvider = new BlaiseIapNodeProvider("EXAMPLE_CLIENT_ID");
    await googleAuthProvider.getAuthHeader();

    // Call for header with should not have expired
    const updatedMockToken = "MockSecondaryTokenCalled";
    mockAuthToken(updatedMockToken);

    const authHeader = await googleAuthProvider.getAuthHeader();

    // Token should not have been updated
    expect(authHeader).toEqual({Authorization: `Bearer ${olderMockToken}`});
    expect(mockedGetGoogleAuthToken).toHaveBeenCalledTimes(1);
});


it("We get a new token when a token is invalid", async () => {
    console.log = jest.fn();
    // Setup old token which is broken
    mockAuthToken("%%%%%");
    const googleAuthProvider = new BlaiseIapNodeProvider("EXAMPLE_CLIENT_ID");
    await googleAuthProvider.getAuthHeader();

    // Call for header again which should update
    const updatedMockToken = "MockSecondaryTokenCalled";
    mockAuthToken(updatedMockToken);

    const authHeader = await googleAuthProvider.getAuthHeader();

    expect(authHeader).toEqual({Authorization: `Bearer ${updatedMockToken}`});
    expect(console.log).toHaveBeenCalledWith("Failed to decode token, Calling for new Google auth Token");
});
