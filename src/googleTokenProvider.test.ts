import { vi, describe, it, expect, beforeEach, afterEach } from "vitest";

const { mockFetchIdToken, mockGetIdTokenClient } = vi.hoisted(() => {
  return {
    mockFetchIdToken: vi.fn(),
    mockGetIdTokenClient: vi.fn(),
  };
});

vi.mock("google-auth-library", () => {
  return {
    GoogleAuth: class {
      getIdTokenClient = mockGetIdTokenClient;
    },
  };
});

import getGoogleAuthToken from "./googleTokenProvider.js";

describe("googleTokenProvider", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    mockGetIdTokenClient.mockResolvedValue({
      idTokenProvider: {
        fetchIdToken: mockFetchIdToken,
      },
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns the token when GoogleAuth succeeds", async () => {
    const expectedToken = "super-secret-google-token";
    const targetAudience = "test-audience";

    mockFetchIdToken.mockResolvedValueOnce(expectedToken);

    const result = await getGoogleAuthToken(targetAudience);

    expect(result).toBe(expectedToken);
    expect(mockGetIdTokenClient).toHaveBeenCalledWith(targetAudience);
    expect(mockFetchIdToken).toHaveBeenCalledWith(targetAudience);
  });

  it("throws an error and logs it when GoogleAuth fails", async () => {
    const errorMessage = "Invalid target audience";
    const targetAudience = "test-audience";

    mockGetIdTokenClient.mockRejectedValueOnce(new Error(errorMessage));

    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await expect(getGoogleAuthToken(targetAudience)).rejects.toThrow(
      `Failed to fetch Google Auth Token: ${errorMessage}`,
    );

    expect(consoleSpy).toHaveBeenCalledWith(
      "Could not get the Google auth token credentials:",
      errorMessage,
    );
  });

  it("throws an error and logs it when GoogleAuth fails with a non-Error object", async () => {
    const nonErrorRejection = "Raw string rejection from Google";
    const targetAudience = "test-audience";

    mockGetIdTokenClient.mockRejectedValueOnce(nonErrorRejection);

    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await expect(getGoogleAuthToken(targetAudience)).rejects.toThrow(
      `Failed to fetch Google Auth Token: ${nonErrorRejection}`,
    );

    expect(consoleSpy).toHaveBeenCalledWith(
      "Could not get the Google auth token credentials:",
      nonErrorRejection,
    );
  });
});
