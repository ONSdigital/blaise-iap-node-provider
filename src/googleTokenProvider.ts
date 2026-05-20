import { GoogleAuth } from "google-auth-library";

const googleAuth = new GoogleAuth();

export async function fetchGoogleIdToken(targetAudience: string): Promise<string> {
  try {
    const client = await googleAuth.getIdTokenClient(targetAudience);

    return await client.idTokenProvider.fetchIdToken(targetAudience);
  } catch (error) {
    throw new Error("Failed to fetch Google ID token.", { cause: error });
  }
}
