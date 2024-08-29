import crypto from "node:crypto";
import { generateRandomId } from "./generateRandomId";
import { getHTMLTemplate } from "./getHTMLTemplate";

async function handleRequest(request: Request, env: Env) {
  const requestUrl = new URL(request.url);

  if (
    request.method === "POST" &&
    requestUrl.pathname.startsWith("/auth/authorize")
  ) {
    const readKey = generateRandomId();
    const writeKey = generateRandomId();
    const codeVerifier = crypto.randomBytes(96).toString("base64url");

    const codeChallenge = crypto
      .createHash("sha256")
      .update(codeVerifier)
      .digest("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

    const authorizeParams = new URLSearchParams({
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      client_id: env.CLIENT_ID,
      redirect_uri: env.REDIRECT_URI,
      response_type: "code",
      state: writeKey,
      scope: env.SCOPE || "",
    });

    const authorizeUrl = `${env.AUTHORIZE_ENDPOINT}?${authorizeParams}`;

    await env.airtableOAuthStore.put(`readKey:${writeKey}`, readKey, {
      expirationTtl: 60,
    });
    await env.airtableOAuthStore.put(`codeVerifier:${writeKey}`, codeVerifier, {
      expirationTtl: 60,
    });

    return new Response(JSON.stringify({ url: authorizeUrl, readKey }), {
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": env.PLUGIN_URI,
      },
    });
  }

  if (
    request.method === "GET" &&
    requestUrl.pathname.startsWith("/auth/redirect")
  ) {
    const authorizationCode = requestUrl.searchParams.get("code");
    const writeKey = requestUrl.searchParams.get("state");

    if (!authorizationCode || !writeKey) {
      return new Response("Missing required parameters", { status: 400 });
    }

    const readKey = await env.airtableOAuthStore.get(`readKey:${writeKey}`);
    const codeVerifier = await env.airtableOAuthStore.get(
      `codeVerifier:${writeKey}`
    );

    if (!readKey || !codeVerifier) {
      return new Response("Invalid or expired request", { status: 400 });
    }

    const tokenParams = new URLSearchParams({
      client_id: env.CLIENT_ID,
      code_verifier: codeVerifier,
      redirect_uri: env.REDIRECT_URI,
      code: authorizationCode,
      grant_type: "authorization_code",
    });

    const encodedCredentials = btoa(`${env.CLIENT_ID}:${env.CLIENT_SECRET}`);

    const tokenResponse = await fetch(env.TOKEN_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${encodedCredentials}`,
      },
      body: tokenParams,
    });

    if (tokenResponse.status !== 200) {
      return new Response(await tokenResponse.text(), {
        status: tokenResponse.status,
      });
    }

    const tokens = await tokenResponse.json();
    await env.airtableOAuthStore.put(
      `tokens:${readKey}`,
      JSON.stringify(tokens),
      {
        expirationTtl: 300,
      }
    );

    return new Response(
      getHTMLTemplate("Authentication successful! You can close this window."),
      {
        headers: { "Content-Type": "text/html" },
      }
    );
  }

  if (
    request.method === "POST" &&
    requestUrl.pathname.startsWith("/auth/poll")
  ) {
    const readKey = requestUrl.searchParams.get("readKey");

    if (!readKey) {
      return new Response("Missing read key URL param", {
        status: 400,
        headers: {
          "Access-Control-Allow-Origin": env.PLUGIN_URI,
        },
      });
    }

    const tokens = await env.airtableOAuthStore.get(`tokens:${readKey}`);

    if (!tokens) {
      return new Response(null, {
        status: 404,
        headers: { "Access-Control-Allow-Origin": env.PLUGIN_URI },
      });
    }

    await env.airtableOAuthStore.delete(`tokens:${readKey}`);

    return new Response(tokens, {
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": env.PLUGIN_URI,
      },
    });
  }

  if (
    request.method === "POST" &&
    requestUrl.pathname.startsWith("/auth/refresh")
  ) {
    const refreshToken = requestUrl.searchParams.get("code");

    if (!refreshToken) {
      return new Response("Missing refresh token URL param", {
        status: 400,
        headers: {
          "Access-Control-Allow-Origin": env.PLUGIN_URI,
        },
      });
    }

    const refreshParams = new URLSearchParams({
      refresh_token: refreshToken,
      client_id: env.CLIENT_ID,
      grant_type: "refresh_token",
    });

    const encodedCredentials = btoa(`${env.CLIENT_ID}:${env.CLIENT_SECRET}`);

    const refreshResponse = await fetch(env.TOKEN_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${encodedCredentials}`,
      },
      body: refreshParams,
    });

    if (refreshResponse.status !== 200) {
      return new Response(await refreshResponse.text(), {
        status: refreshResponse.status,
      });
    }

    const tokens = await refreshResponse.json();

    return new Response(JSON.stringify(tokens), {
      headers: {
        "Access-Control-Allow-Origin": env.PLUGIN_URI,
      },
    });
  }

  if (request.method === "GET" && requestUrl.pathname === "/") {
    return new Response("✅ OAuth Worker is up and running!");
  }

  return new Response("Page not found", {
    status: 404,
    headers: {
      "Access-Control-Allow-Origin": env.PLUGIN_URI,
    },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, env).catch((error) => {
      const message = error instanceof Error ? error.message : "Unknown";

      return new Response(`😔 Internal error: ${message}`, {
        status: 500,
        headers: {
          "Access-Control-Allow-Origin": env.PLUGIN_URI,
        },
      });
    });
  },
};
