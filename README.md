# Blaise IAP Node Provider 🪪

A Node.js utility for generating and managing Google Identity-Aware Proxy (IAP) authentication headers. Designed for service-to-service communication within Google Cloud Platform (GCP).

This provider handles Google Auth ID token generation, token caching, and automatic token refreshing, ensuring secure downstream requests maintain low latency.

## 📝 Usage

Add this repository to your Node/TypeScript project as a dependency, specifying the target release version:

```Shell
yarn add git+https://github.com/ONSdigital/blaise-iap-node-provider#<RELEASE_VERSION>
```

Release versions can be found on this repo's [GitHub releases](https://github.com/ONSdigital/blaise-iap-node-provider/releases).

### Implementation Example

The provider requires the Client ID of the target IAP-secured service. It exposes a single `getAuthHeader()` method which returns an object that can be spread directly into the headers of modern HTTP clients (like Axios or Fetch).

```TypeScript
import BlaiseIapProvider from "blaise-iap-node-provider";
import axios from "axios";

// Initialise the provider with the target service's IAP Client ID
const TARGET_CLIENT_ID = process.env.TARGET_CLIENT_ID || "";
const iapProvider = new BlaiseIapProvider(TARGET_CLIENT_ID);

export async function fetchSecureData() {
  try {
    // Retrieve the auth header.
    // This resolves instantly if a cached token is valid, or fetches a new one if expired.
    const authHeader = await iapProvider.getAuthHeader();
    // Inject the header into your HTTP client
    const response = await axios.get("https://example-secure-api.com/v1/data", {
      headers: {
        ...authHeader, // Injects { Authorization: "Bearer <token>" }
        "Content-Type": "application/json",
      },
    });
    return response.data;
  } catch (error) {
    console.error("Failed to fetch secure data", error);
    throw error;
  }
}
```

### Authentication Context

This provider relies on google-auth-library. For the token generation to succeed, the environment running this code must have valid Google Cloud credentials (e.g., running on a GCP compute instance with an attached service account, or utilising a local GOOGLE_APPLICATION_CREDENTIALS JSON keyfile during development).

## 🛠️ Development

### Getting Started

Clone the repository:

```Shell
git clone https://github.com/ONSdigital/blaise-iap-node-provider.git
```

Install dependencies:

```Shell
yarn install
```

### Quality Control

Ensure any changes to token management or caching logic are covered by unit tests.

To run tests:

```Shell
yarn test
```

To run linting:

```Shell
yarn lint
```

To automatically fix standard linting issues:

```Shell
yarn lint-fix
```

### Releasing

After merging to main, [create a new release](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository) with appropriate release notes. The `package.json` version is automatically updated via GitHub Actions when a release is published.
