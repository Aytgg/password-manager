import type { AuthConfig } from "convex/server";

export default {
  providers: [
    {
      domain: "https://dynamic-oriole-8705.clerk.accounts.dev",
      applicationID: "convex",
    },
  ],
} satisfies AuthConfig;
