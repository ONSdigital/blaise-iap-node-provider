import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

import { fetchGoogleIdToken } from "./googleTokenProvider.js";

describe("fetchGoogleIdToken", () => {
  beforeEach(() => {
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

    const result = await fetchGoogleIdToken(targetAudience);

    expect(result).toBe(expectedToken);
    expect(mockGetIdTokenClient).toHaveBeenCalledWith(targetAudience);
    expect(mockFetchIdToken).toHaveBeenCalledWith(targetAudience);
  });

  it("wraps upstream errors without logging from the library", async () => {
    const errorMessage = "Invalid target audience";
    const targetAudience = "test-audience";

    mockGetIdTokenClient.mockRejectedValueOnce(new Error(errorMessage));

    await expect(fetchGoogleIdToken(targetAudience)).rejects.toMatchObject({
      cause: expect.objectContaining({ message: errorMessage }),
      message: "Failed to fetch Google ID token.",
    });

    expect(mockFetchIdToken).not.toHaveBeenCalled();
  });

  it("preserves non-Error rejections as the error cause", async () => {
    const nonErrorRejection = "Raw string rejection from Google";
    const targetAudience = "test-audience";

    mockGetIdTokenClient.mockRejectedValueOnce(nonErrorRejection);

    await expect(fetchGoogleIdToken(targetAudience)).rejects.toMatchObject({
      cause: nonErrorRejection,
      message: "Failed to fetch Google ID token.",
    });
  });
});
