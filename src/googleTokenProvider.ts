import { GoogleAuth } from "google-auth-library";

const auth = new GoogleAuth();

export async function getGoogleAuthToken(targetAudience: string): Promise<string> {
  try {
    const client = await auth.getIdTokenClient(targetAudience);

    return await client.idTokenProvider.fetchIdToken(targetAudience);
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);

    console.error("Could not get the Google auth token credentials:", errorMessage);

    throw new Error(`Failed to fetch Google Auth Token: ${errorMessage}`, { cause: error });
  }
}
