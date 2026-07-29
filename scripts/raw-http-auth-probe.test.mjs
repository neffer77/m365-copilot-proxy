import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  statSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  assertDisposableCachePath,
  assertIdTokenNonce,
  buildAuthorizationUrl,
  buildDryRunPlan,
  buildHttpTemplates,
  CLIENT_ID,
  createRawTokenCache,
  discoverEndpoints,
  generatePkce,
  NATIVECLIENT_REDIRECT_URI,
  parseArgs,
  pollDeviceToken,
  readRawTokenCache,
  recordBrowserAuthorization,
  requestJson,
  sanitizeError,
  tokenSummary,
  writeRawTokenCache,
  writeRedactedReport,
} from "./raw-http-auth-lib.mjs";

function fakeJwt(payload) {
  const header = Buffer.from(
    JSON.stringify({ alg: "none", typ: "JWT" }),
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${header}.${body}.signature`;
}

function fakeTokenResponse(overrides = {}) {
  return {
    access_token: fakeJwt({
      appid: CLIENT_ID,
      aud: "https://substrate.office.com/sydney",
      oid: "12345678-aaaa-bbbb-cccc-123456789012",
      scp: "scope.b scope.a",
      tid: "87654321-aaaa-bbbb-cccc-210987654321",
    }),
    expires_in: 3600,
    id_token: fakeJwt({
      nonce: "expected-nonce",
      oid: "12345678-aaaa-bbbb-cccc-123456789012",
      preferred_username: "connor@example.com",
      tid: "87654321-aaaa-bbbb-cccc-210987654321",
    }),
    refresh_token: "sensitive-refresh-token",
    scope: "scope.a scope.b",
    token_type: "Bearer",
    ...overrides,
  };
}

describe("raw HTTP auth argument parsing", () => {
  it("defaults to an inert enterprise browser flow", () => {
    const options = parseArgs([]);
    expect(options.execute).toBe(false);
    expect(options.method).toBe("browser");
    expect(options.authority).toBe(
      "https://login.microsoftonline.com/organizations",
    );
    expect(options.audiences).toEqual(["chat", "bap", "powerplatform"]);
  });

  it("supports a discovery-only raw HTTP execution", () => {
    const options = parseArgs(["--discovery-only", "--execute"]);
    expect(options.discoveryOnly).toBe(true);
    expect(options.execute).toBe(true);
    expect(buildDryRunPlan(options).join("\n")).not.toMatch(
      /authorization code|device authorization/i,
    );
  });

  it("prints inspectable raw requests with secret placeholders", () => {
    const options = parseArgs([
      "--method=device-code",
      "--audiences=chat",
      "--show-http",
    ]);
    const templates = buildHttpTemplates(options).join("\n");
    expect(options.showHttp).toBe(true);
    expect(templates).toContain(
      "GET https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration",
    );
    expect(templates).toContain("Content-Type: application/x-www-form-urlencoded");
    expect(templates).toContain(
      "grant_type=urn:ietf:params:oauth:grant-type:device_code",
    );
    expect(templates).toContain("refresh_token=<redacted-refresh-token>");
    expect(templates).not.toContain("sensitive-refresh-token");
  });

  it("uses the registered nativeclient redirect for the default browser flow", () => {
    const templates = buildHttpTemplates(
      parseArgs(["--method=browser", "--audiences=chat", "--show-http"]),
    ).join("\n");
    expect(templates).toContain(
      `redirect_uri=${NATIVECLIENT_REDIRECT_URI}`,
    );
    expect(templates).not.toContain("http://localhost");
  });

  it("accepts device code and the legacy nativeclient method alias", () => {
    const device = parseArgs([
      "--",
      "--method=device-code",
      "--authority",
      "contoso.onmicrosoft.com",
      "--audiences=chat,bap",
      "--incremental-interaction",
      "--execute",
    ]);
    expect(device.authority).toBe(
      "https://login.microsoftonline.com/contoso.onmicrosoft.com",
    );
    expect(device.method).toBe("device-code");
    expect(device.execute).toBe(true);

    expect(
      parseArgs(["--method=nativeclient-visible"]).method,
    ).toBe("nativeclient-browser");
  });

  it("rejects unknown options, audiences, and non-Microsoft authorities", () => {
    expect(() => parseArgs(["--surprise"])).toThrow(/Unknown option/);
    expect(() => parseArgs(["--audiences=graph"])).toThrow(/Unknown audience/);
    expect(() =>
      parseArgs(["--authority=https://example.com/tenant"]),
    ).toThrow(/authority/);
  });
});

describe("raw HTTP auth cache safety", () => {
  it("refuses production cache and credential files", () => {
    for (const filename of ["msal-cache.json", "secrets.json"]) {
      expect(() =>
        assertDisposableCachePath(
          `/safe-home/.config/opencode-m365/${filename}`,
          "/safe-home",
        ),
      ).toThrow(/production credential\/cache/);
    }
  });

  it.runIf(process.platform !== "win32")(
    "refuses a symlink alias to a production cache",
    () => {
      const homeDirectory = mkdtempSync(
        join(tmpdir(), "raw-auth-probe-home-"),
      );
      const productionDirectory = join(
        homeDirectory,
        ".config",
        "opencode-m365",
      );
      const aliasDirectory = join(homeDirectory, "cache-alias");
      mkdirSync(productionDirectory, { recursive: true });
      symlinkSync(productionDirectory, aliasDirectory, "dir");

      expect(() =>
        assertDisposableCachePath(
          join(aliasDirectory, "msal-cache.json"),
          homeDirectory,
        ),
      ).toThrow(/production credential\/cache/);
    },
  );

  it("persists and reloads only the isolated raw refresh state privately", () => {
    const directory = mkdtempSync(join(tmpdir(), "raw-auth-cache-test-"));
    const cacheFile = join(directory, "cache.json");
    const cache = createRawTokenCache({
      authority: "organizations",
      tokenResponse: fakeTokenResponse(),
    });
    writeRawTokenCache(cacheFile, cache);

    const persisted = readRawTokenCache(cacheFile);
    expect(persisted.protocol).toBe("oauth2-raw-http");
    expect(persisted.refreshToken).toBe("sensitive-refresh-token");
    expect(readFileSync(cacheFile, "utf8")).not.toContain("access_token");
    if (process.platform !== "win32") {
      expect(statSync(cacheFile).mode & 0o777).toBe(0o600);
    }
  });

  it("writes redacted reports without broad permissions", () => {
    const directory = mkdtempSync(join(tmpdir(), "raw-auth-report-test-"));
    const reportFile = join(directory, "report.json");
    writeRedactedReport(reportFile, { status: "ok" });
    expect(JSON.parse(readFileSync(reportFile, "utf8"))).toEqual({
      status: "ok",
    });
    if (process.platform !== "win32") {
      expect(statSync(reportFile).mode & 0o777).toBe(0o600);
    }
  });
});

describe("raw HTTP OAuth construction and parsing", () => {
  it("generates RFC 7636-shaped PKCE values", () => {
    const { challenge, verifier } = generatePkce();
    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
    expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(challenge).not.toBe(verifier);
  });

  it("builds an authorization-code request with PKCE, state, and nonce", () => {
    const url = new URL(
      buildAuthorizationUrl({
        authorizationEndpoint:
          "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
        challenge: "challenge",
        nonce: "nonce",
        prompt: "select_account",
        redirectUri: NATIVECLIENT_REDIRECT_URI,
        scopes: ["resource/scope", "openid", "offline_access"],
        state: "state",
      }),
    );
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("redirect_uri")).toBe(
      NATIVECLIENT_REDIRECT_URI,
    );
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("state")).toBe("state");
    expect(url.searchParams.get("nonce")).toBe("nonce");
    expect(url.searchParams.get("scope")).toContain("offline_access");
  });

  it("performs a form-encoded request and traces names, never values", async () => {
    const trace = [];
    const fetchImpl = vi.fn(async (_url, init) => {
      expect(init.method).toBe("POST");
      expect(init.headers["content-type"]).toBe(
        "application/x-www-form-urlencoded",
      );
      expect(init.body).toContain("refresh_token=very-secret");
      return new Response(
        JSON.stringify({
          access_token: "access-secret",
          refresh_token: "refresh-secret",
          token_type: "Bearer",
        }),
        { status: 200 },
      );
    });

    const result = await requestJson({
      fetchImpl,
      form: {
        client_id: CLIENT_ID,
        refresh_token: "very-secret",
      },
      method: "POST",
      step: "test-token",
      trace,
      url: "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
    });
    expect(result.ok).toBe(true);
    expect(trace[0].requestFields).toEqual([
      "client_id",
      "refresh_token",
    ]);
    expect(trace[0].responseFields).toContain("access_token");
    expect(JSON.stringify(trace)).not.toContain("very-secret");
    expect(JSON.stringify(trace)).not.toContain("access-secret");
  });

  it("redacts tenant identifiers and every authorization query value", () => {
    const trace = [];
    recordBrowserAuthorization(
      trace,
      "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize?client_id=client&state=state-secret&nonce=nonce-secret",
      "system-browser",
    );
    expect(trace[0].url).toContain("<tenant>");
    expect(trace[0].url).not.toContain("contoso.onmicrosoft.com");
    expect(trace[0].queryFields).toEqual([
      "client_id",
      "nonce",
      "state",
    ]);
    expect(JSON.stringify(trace)).not.toContain("state-secret");
    expect(JSON.stringify(trace)).not.toContain("nonce-secret");
  });

  it("follows only validated Microsoft redirects while preserving a POST", async () => {
    const calls = [];
    const trace = [];
    const result = await requestJson({
      fetchImpl: async (url, init) => {
        calls.push({ body: init.body, method: init.method, url });
        if (calls.length === 1) {
          return new Response(null, {
            headers: {
              location:
                "https://login.microsoftonline.com/organizations/oauth2/v2.0/token2",
            },
            status: 307,
          });
        }
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      },
      form: { refresh_token: "secret" },
      method: "POST",
      step: "redirect-test",
      trace,
      url: "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
    });
    expect(result.ok).toBe(true);
    expect(calls).toHaveLength(2);
    expect(calls[1].method).toBe("POST");
    expect(calls[1].body).toBe(calls[0].body);
    expect(trace[0]).toMatchObject({
      status: 307,
      step: "redirect-test-redirect",
    });
  });

  it("discovers and validates Microsoft endpoints from raw JSON", async () => {
    const trace = [];
    const endpoints = await discoverEndpoints("organizations", {
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            authorization_endpoint:
              "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
            issuer:
              "https://login.microsoftonline.com/{tenantid}/v2.0",
            token_endpoint:
              "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
          }),
          { status: 200 },
        ),
      trace,
    });
    expect(endpoints.authorizationEndpoint).toMatch(/\/authorize$/);
    expect(endpoints.tokenEndpoint).toMatch(/\/token$/);
    expect(endpoints.deviceAuthorizationEndpoint).toMatch(/\/devicecode$/);
    expect(trace[0]).toMatchObject({
      method: "GET",
      status: 200,
      step: "oidc-discovery",
      transport: "raw-fetch",
    });
  });

  it("polls device code through pending and then parses success", async () => {
    let clock = 0;
    let attempt = 0;
    const trace = [];
    const token = await pollDeviceToken({
      deviceAuthorization: {
        device_code: "device-secret",
        expires_in: 60,
        interval: 1,
      },
      fetchImpl: async () => {
        attempt += 1;
        if (attempt === 1) {
          return new Response(
            JSON.stringify({ error: "authorization_pending" }),
            { status: 400 },
          );
        }
        return new Response(
          JSON.stringify({
            access_token: "access-secret",
            token_type: "Bearer",
          }),
          { status: 200 },
        );
      },
      now: () => clock,
      sleep: async (duration) => {
        clock += duration;
      },
      timeoutMs: 30_000,
      tokenEndpoint:
        "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
      trace,
    });
    expect(token.access_token).toBe("access-secret");
    expect(trace).toHaveLength(2);
    expect(trace[0].oauthError).toBe("authorization_pending");
    expect(JSON.stringify(trace)).not.toContain("device-secret");
  });
});

describe("raw HTTP auth redaction and identity", () => {
  it("summarizes tokens without retaining tokens or full identity", () => {
    const response = fakeTokenResponse();
    const summary = tokenSummary(response, {
      audience: "chat",
      now: Date.parse("2026-07-28T00:00:00Z"),
    });
    expect(summary.account.username).toBe("c***@example.com");
    expect(summary.account.objectId).toBe("12345678…");
    expect(summary.audienceMatchesExpected).toBe(true);
    expect(summary.enterpriseTenantBacked).toBe(true);
    expect(summary.scopes).toEqual(["scope.a", "scope.b"]);
    expect(JSON.stringify(summary)).not.toContain(response.access_token);
    expect(JSON.stringify(summary)).not.toContain(response.refresh_token);
    expect(JSON.stringify(summary)).not.toContain(
      "12345678-aaaa-bbbb-cccc-123456789012",
    );
  });

  it("validates the OIDC nonce", () => {
    expect(() =>
      assertIdTokenNonce(fakeTokenResponse(), "expected-nonce"),
    ).not.toThrow();
    expect(() =>
      assertIdTokenNonce(fakeTokenResponse(), "wrong-nonce"),
    ).toThrow(/nonce mismatch/);
  });

  it("redacts OAuth secrets, emails, GUIDs, and JWTs from errors", () => {
    const error = new Error(
      "user@example.com refresh_token=secret device_code=device-secret 12345678-aaaa-bbbb-cccc-123456789012 eyJaaaaaaaaaaaaaaaaaaaa.eyJbbbbbbbbbbbbbbbbbbbb.signature",
    );
    const safe = sanitizeError(error);
    expect(safe.message).not.toContain("user@example.com");
    expect(safe.message).not.toContain("device-secret");
    expect(safe.message).not.toContain("12345678-aaaa");
    expect(safe.message).toContain("<redacted-email>");
  });
});

describe("raw HTTP auth dry-run", () => {
  it("describes raw discovery, exchange, refresh, and redacted tracing", () => {
    const plan = buildDryRunPlan(
      parseArgs(["--incremental-interaction"]),
    ).join("\n");
    expect(plan).toMatch(/OIDC discovery/);
    expect(plan).toMatch(/PKCE/);
    expect(plan).toMatch(/refresh_token grant/);
    expect(plan).toMatch(/HTTP metadata trace/);
    expect(plan).not.toMatch(/MSAL/);
  });

});
