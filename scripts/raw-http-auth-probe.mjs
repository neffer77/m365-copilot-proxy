#!/usr/bin/env node
/**
 * Phase 0 enterprise M365 raw-HTTP OAuth compatibility probe.
 *
 * Every protocol request owned by this tool uses Node fetch() directly. A
 * user-agent is still required for Microsoft sign-in, MFA, and Conditional
 * Access, but no authentication SDK fills, sends, or caches credentials.
 */

import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertDisposableCachePath,
  assertIdTokenNonce,
  assertSameIdentity,
  authorityDescriptor,
  buildAuthorizationUrl,
  buildDryRunPlan,
  buildHttpTemplates,
  CLIENT_ID,
  createRawTokenCache,
  discoverEndpoints,
  exchangeAuthorizationCode,
  generatePkce,
  NATIVECLIENT_REDIRECT_URI,
  OAuthProtocolError,
  parseArgs,
  pollDeviceToken,
  randomOAuthValue,
  readRawTokenCache,
  recordBrowserAuthorization,
  refreshAccessToken,
  requestDeviceAuthorization,
  requestScopesForAudience,
  sanitizeError,
  tokenIdentity,
  tokenSummary,
  writeRawTokenCache,
  writeRedactedReport,
} from "./raw-http-auth-lib.mjs";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = dirname(SCRIPT_DIRECTORY);
const coreRequire = createRequire(
  new URL("../packages/core/package.json", import.meta.url),
);

const HELP = `Phase 0 enterprise M365 raw-HTTP OAuth probe

This tool uses raw HTTP for OIDC discovery, device authorization, authorization-code
exchange, refresh-token grants, and JSON/JWT parsing. It does not use MSAL.

Dry run (default; no network or browser):
  pnpm run probe:auth -- --method=browser --authority=organizations

Run one isolated enterprise flow:
  pnpm run probe:auth -- --method=browser --authority=organizations --audiences=chat --execute
  pnpm run probe:auth -- --method=device-code --authority=organizations --audiences=chat --execute

Options:
  --method=browser|device-code|nativeclient-browser
  --authority=organizations|common|<tenant-id-or-domain>
  --audiences=chat,bap,powerplatform
  --discovery-only          Send only the raw OIDC metadata GET; never start sign-in
  --incremental-interaction  Interact again if another resource cannot use the refresh token
  --silent-only             Test refresh grants from an existing --cache
  --cache=<absolute-path>   Explicit isolated raw-OAuth cache
  --reuse-cache             Permit an existing explicit cache
  --keep-cache              Retain an auto-created temporary cache
  --login-hint=<email>      Browser hint only; never persisted in the report
  --prompt=select_account|login|none
  --no-open                 Device code: print the URL instead of launching it
  --chromium=<path>         Chromium for the browser flow
  --browser-profile=<path>  Isolated persistent profile for the browser flow
  --headless-browser        Reuse a preauthenticated browser profile headlessly
  --show-http               Dry-run: print redacted raw request templates
  --timeout=<seconds>       30-900 (default 180)
  --json-out=<path>         Redacted report destination
  --allow-non-tty           Deliberately allow execution without a terminal
  --execute                 Required for every Microsoft network/auth request
  --help

Enterprise behavior:
  - "organizations" accepts only Microsoft Entra work/school accounts.
  - A tenant ID/domain restricts sign-in to that enterprise directory.
  - The Azure/Entra sign-in page is also the identity page for enterprise M365.

Safety:
  - The default raw refresh-token cache is temporary and deleted after the run.
  - Production msal-cache.json and secrets.json are always refused.
  - HTTP traces contain field names/statuses only, never request values or tokens.
  - Reports redact account IDs, tenant IDs, usernames, codes, and tokens.
  - The probe sends no M365 chat turn and consumes zero chat messages.
`;

function timestampId() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function printDryRun(options) {
  console.log("DRY RUN — no Microsoft request or browser interaction will occur.\n");
  console.log("protocol:   raw HTTP OAuth 2.0 / OIDC (no MSAL)");
  console.log(`method:     ${options.method}`);
  console.log(`authority:  ${options.authority}`);
  console.log(`audiences:  ${options.audiences.join(", ")}`);
  console.log(`cache:      ${options.cache ? "explicit isolated path" : "temporary"}`);
  console.log("\nplanned requests:");
  buildDryRunPlan(options).forEach((step, index) => {
    console.log(`  ${index + 1}. ${step}`);
  });
  if (options.showHttp) {
    console.log("\nraw HTTP templates (secrets are placeholders):");
    buildHttpTemplates(options).forEach((template, index) => {
      console.log(`\n[${index + 1}]\n${template}`);
    });
  }
  console.log("\nAdd --execute to send these requests.");
}

async function openSystemBrowser(url, noOpen, label = "Microsoft sign-in") {
  if (noOpen) {
    console.log(`\nOpen this one-time ${label} URL in your browser:`);
    console.log(url);
    return;
  }

  const command =
    process.platform === "darwin"
      ? { file: "open", args: [url] }
      : process.platform === "win32"
        ? { file: "explorer.exe", args: [url] }
        : { file: "xdg-open", args: [url] };

  try {
    await new Promise((resolveSpawn, rejectSpawn) => {
      const child = spawn(command.file, command.args, {
        detached: true,
        stdio: "ignore",
      });
      child.once("error", rejectSpawn);
      child.once("spawn", () => {
        child.unref();
        resolveSpawn();
      });
    });
    console.log(`Opened ${label} in the system browser.`);
  } catch (error) {
    console.log(`Could not launch a browser (${sanitizeError(error).message}).`);
    console.log(`Open this one-time ${label} URL manually:`);
    console.log(url);
  }
}

function callbackError(parameters) {
  if (!parameters?.error) return null;
  return new OAuthProtocolError(
    `${parameters.error}: ${parameters.error_description ?? "Microsoft authorization failed"}`,
    {
      correlationId: parameters.correlation_id,
      oauthError: parameters.error,
      subError: parameters.suberror,
    },
  );
}

async function captureNativeclientResponse({
  authorizationUrl,
  options,
  profileDirectory,
  state,
}) {
  const { chromium } = coreRequire("playwright");
  mkdirSync(profileDirectory, { recursive: true, mode: 0o700 });
  try {
    chmodSync(profileDirectory, 0o700);
  } catch {
    // Best effort on non-POSIX platforms.
  }

  const context = await chromium.launchPersistentContext(profileDirectory, {
    args:
      typeof process.getuid === "function" && process.getuid() === 0
        ? ["--no-sandbox"]
        : [],
    executablePath:
      options.chromium ?? process.env.CHROMIUM_PATH ?? undefined,
    headless: options.headlessBrowser,
  });
  const page = context.pages()[0] ?? (await context.newPage());

  try {
    return await new Promise((resolveCallback, rejectCallback) => {
      let settled = false;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        if (error) rejectCallback(error);
        else resolveCallback(value);
      };
      const timeout = setTimeout(
        () =>
          finish(
            new Error(
              `Nativeclient browser authorization timed out after ${options.timeoutMs / 1000}s`,
            ),
          ),
        options.timeoutMs,
      );

      page.on("request", (request) => {
        try {
          const url = new URL(request.url());
          const isNativeclient =
            url.origin === "https://login.microsoftonline.com" &&
            /\/oauth2\/nativeclient$/i.test(url.pathname);
          if (!isNativeclient) return;
          const parameters = Object.fromEntries(url.searchParams.entries());
          if (parameters.state !== state) {
            finish(new Error("Microsoft authorization state mismatch"));
            return;
          }
          finish(null, parameters);
        } catch {
          // Ignore unrelated browser requests.
        }
      });
      page.once("close", () => {
        finish(
          new Error(
            "Nativeclient browser was closed before Microsoft authorization completed",
          ),
        );
      });

      page.goto(authorizationUrl, {
        timeout: options.timeoutMs,
        waitUntil: "domcontentloaded",
      }).catch((error) => {
        if (!settled && /ERR_ABORTED|wrongplace/i.test(String(error?.message))) {
          return;
        }
        if (!settled && page.isClosed()) finish(error);
      });

      console.log(
        options.headlessBrowser
          ? "Opened an isolated headless browser. This succeeds only if its profile already has usable enterprise SSO."
          : "Opened an isolated visible browser. Complete Microsoft sign-in there; the tool never fills credentials.",
      );
    });
  } finally {
    await context.close();
  }
}

async function acquireWithNativeclientBrowser({
  endpoints,
  options,
  profileDirectory,
  scopes,
  trace,
}) {
  const state = randomOAuthValue();
  const nonce = randomOAuthValue();
  const { challenge, verifier } = generatePkce();
  const authorizationUrl = buildAuthorizationUrl({
    authorizationEndpoint: endpoints.authorizationEndpoint,
    challenge,
    loginHint: options.loginHint,
    nonce,
    prompt: options.prompt,
    redirectUri: NATIVECLIENT_REDIRECT_URI,
    scopes,
    state,
  });
  recordBrowserAuthorization(
    trace,
    authorizationUrl,
    options.headlessBrowser
      ? "playwright-headless-user-agent"
      : "playwright-visible-user-agent",
  );
  const parameters = await captureNativeclientResponse({
    authorizationUrl,
    options,
    profileDirectory,
    state,
  });
  const oauthError = callbackError(parameters);
  if (oauthError) throw oauthError;
  if (!parameters.code) {
    throw new Error("Microsoft nativeclient response returned no authorization code");
  }
  const tokenResponse = await exchangeAuthorizationCode({
    code: parameters.code,
    redirectUri: NATIVECLIENT_REDIRECT_URI,
    scopes,
    timeoutMs: options.timeoutMs,
    tokenEndpoint: endpoints.tokenEndpoint,
    trace,
    verifier,
  });
  assertIdTokenNonce(tokenResponse, nonce);
  return tokenResponse;
}

async function acquireWithDeviceCode({
  endpoints,
  options,
  scopes,
  trace,
}) {
  const deviceAuthorization = await requestDeviceAuthorization({
    deviceAuthorizationEndpoint: endpoints.deviceAuthorizationEndpoint,
    scopes,
    timeoutMs: options.timeoutMs,
    trace,
  });
  console.log("\nMicrosoft enterprise device sign-in:");
  console.log(`  URL:  ${deviceAuthorization.verification_uri}`);
  console.log(`  Code: ${deviceAuthorization.user_code}`);
  console.log(
    "The short-lived code is shown only in this terminal and is never written to the report.",
  );

  const browserUrl =
    deviceAuthorization.verification_uri_complete ??
    deviceAuthorization.verification_uri;
  await openSystemBrowser(
    browserUrl,
    options.noOpen,
    "Microsoft device sign-in",
  );
  return pollDeviceToken({
    deviceAuthorization,
    timeoutMs: options.timeoutMs,
    tokenEndpoint: endpoints.tokenEndpoint,
    trace,
  });
}

async function acquireInteractively({
  audience,
  endpoints,
  options,
  profileDirectory,
  trace,
}) {
  const scopes = requestScopesForAudience(audience);
  if (options.method === "device-code") {
    return acquireWithDeviceCode({
      endpoints,
      options,
      scopes,
      trace,
    });
  }
  return acquireWithNativeclientBrowser({
    endpoints,
    options,
    profileDirectory,
    scopes,
    trace,
  });
}

function validatedSummary(tokenResponse, audience) {
  const summary = tokenSummary(tokenResponse, { audience });
  if (!summary.enterpriseTenantBacked) {
    throw new Error(
      `${audience} token is not verifiably associated with an enterprise tenant`,
    );
  }
  if (summary.audienceMatchesExpected === false) {
    throw new Error(
      `${audience} token audience did not match the expected M365 resource`,
    );
  }
  if (
    summary.authorizedParty &&
    String(summary.authorizedParty).toLowerCase() !== CLIENT_ID
  ) {
    throw new Error(
      `${audience} token was issued to an unexpected client application`,
    );
  }
  return summary;
}

function persistTokenResponse({
  authority,
  cacheFile,
  previousCache,
  tokenResponse,
}) {
  const cache = createRawTokenCache({
    authority,
    previousCache,
    tokenResponse,
  });
  writeRawTokenCache(cacheFile, cache);
  return cache;
}

function readCompatibleCache(cacheFile, options) {
  const cache = readRawTokenCache(cacheFile);
  if (cache.clientId !== CLIENT_ID) {
    throw new Error("The isolated cache belongs to a different client ID");
  }
  if (cache.authority !== options.authority) {
    throw new Error(
      "The isolated cache authority differs from the requested authority",
    );
  }
  return cache;
}

async function refreshAudience({
  audience,
  cacheFile,
  endpoints,
  options,
  trace,
}) {
  const cache = readCompatibleCache(cacheFile, options);
  const tokenResponse = await refreshAccessToken({
    refreshToken: cache.refreshToken,
    scopes: requestScopesForAudience(audience),
    timeoutMs: options.timeoutMs,
    tokenEndpoint: endpoints.tokenEndpoint,
    trace,
  });
  assertSameIdentity(cache.accountFingerprint, tokenResponse);
  const nextCache = persistTokenResponse({
    authority: options.authority,
    cacheFile,
    previousCache: cache,
    tokenResponse,
  });
  return { cache: nextCache, tokenResponse };
}

async function runMatrix({
  cacheFile,
  endpoints,
  options,
  profileDirectory,
  report,
}) {
  if (options.silentOnly) {
    if (!options.cache || !options.reuseCache) {
      throw new Error("--silent-only requires --cache=<path> and --reuse-cache");
    }
    for (const audience of options.audiences) {
      try {
        const refreshed = await refreshAudience({
          audience,
          cacheFile,
          endpoints,
          options,
          trace: report.httpTrace,
        });
        report.audiences[audience] = {
          silent: {
            mechanism: "raw-http-refresh-token",
            ok: true,
            token: validatedSummary(refreshed.tokenResponse, audience),
          },
        };
        console.log(`[${audience}] raw refresh grant: OK`);
      } catch (error) {
        report.audiences[audience] = {
          silent: { error: sanitizeError(error), ok: false },
        };
        console.log(
          `[${audience}] raw refresh grant: FAILED (${sanitizeError(error).message})`,
        );
      }
    }
    return;
  }

  const firstAudience = options.audiences[0];
  console.log(
    `[${firstAudience}] starting ${options.method} against ${options.authority}`,
  );
  const firstToken = await acquireInteractively({
    audience: firstAudience,
    endpoints,
    options,
    profileDirectory,
    trace: report.httpTrace,
  });
  const firstIdentity = tokenIdentity(firstToken);
  const firstSummary = validatedSummary(firstToken, firstAudience);
  report.identity = {
    accountFingerprint: `${firstIdentity.fingerprint.slice(0, 12)}…`,
    enterpriseTenantBacked: true,
    objectId: firstSummary.account.objectId,
    tenantId: firstSummary.account.tenantId,
    username: firstSummary.account.username,
  };
  report.audiences[firstAudience] = {
    interactive: {
      method: options.method,
      ok: true,
      protocol: "raw-http-oauth2",
      token: firstSummary,
    },
  };
  persistTokenResponse({
    authority: options.authority,
    cacheFile,
    previousCache: null,
    tokenResponse: firstToken,
  });
  console.log(`[${firstAudience}] raw interactive acquisition: OK`);

  const restart = await refreshAudience({
    audience: firstAudience,
    cacheFile,
    endpoints,
    options,
    trace: report.httpTrace,
  });
  report.audiences[firstAudience].restartSilent = {
    mechanism: "raw-http-refresh-token",
    ok: true,
    token: validatedSummary(restart.tokenResponse, firstAudience),
  };
  console.log(`[${firstAudience}] disk-cache raw refresh: OK`);

  for (const audience of options.audiences.slice(1)) {
    try {
      const refreshed = await refreshAudience({
        audience,
        cacheFile,
        endpoints,
        options,
        trace: report.httpTrace,
      });
      report.audiences[audience] = {
        silent: {
          mechanism: "raw-http-refresh-token",
          ok: true,
          token: validatedSummary(refreshed.tokenResponse, audience),
        },
      };
      console.log(`[${audience}] incremental raw refresh: OK`);
      continue;
    } catch (error) {
      report.audiences[audience] = {
        silent: { error: sanitizeError(error), ok: false },
      };
      console.log(
        `[${audience}] incremental raw refresh: FAILED (${sanitizeError(error).message})`,
      );
    }

    if (!options.incrementalInteraction) continue;

    const previousCache = readCompatibleCache(cacheFile, options);
    const tokenResponse = await acquireInteractively({
      audience,
      endpoints,
      options,
      profileDirectory,
      trace: report.httpTrace,
    });
    assertSameIdentity(previousCache.accountFingerprint, tokenResponse);
    report.audiences[audience].interactive = {
      method: options.method,
      ok: true,
      protocol: "raw-http-oauth2",
      token: validatedSummary(tokenResponse, audience),
    };
    persistTokenResponse({
      authority: options.authority,
      cacheFile,
      previousCache,
      tokenResponse,
    });
    console.log(`[${audience}] incremental raw interaction: OK`);

    const restartResult = await refreshAudience({
      audience,
      cacheFile,
      endpoints,
      options,
      trace: report.httpTrace,
    });
    report.audiences[audience].restartSilent = {
      mechanism: "raw-http-refresh-token",
      ok: true,
      token: validatedSummary(restartResult.tokenResponse, audience),
    };
    console.log(`[${audience}] post-interaction raw refresh: OK`);
  }
}

let options;
try {
  options = parseArgs(process.argv.slice(2));
  if (
    options.headlessBrowser &&
    !["browser", "nativeclient-browser"].includes(options.method)
  ) {
    throw new Error(
      "--headless-browser requires --method=browser or --method=nativeclient-browser",
    );
  }
} catch (error) {
  console.error(`Argument error: ${error.message}\n`);
  console.error(HELP);
  process.exit(2);
}

if (options.help) {
  console.log(HELP);
  process.exit(0);
}

if (!options.execute) {
  printDryRun(options);
  process.exit(0);
}

if (
  !process.stdout.isTTY &&
  !options.allowNonTty &&
  !options.discoveryOnly &&
  !options.silentOnly
) {
  console.error(
    "Refusing an authentication probe without a TTY. Re-run in a terminal, or pass --allow-non-tty deliberately.",
  );
  process.exit(2);
}

const runId = timestampId();
const reportDirectory = join(
  REPOSITORY_ROOT,
  "scripts",
  "raw-http-auth-probe-out",
);
mkdirSync(reportDirectory, { recursive: true, mode: 0o700 });
try {
  chmodSync(reportDirectory, 0o700);
} catch {
  // Best effort on platforms that do not support POSIX modes.
}

let reportFile;
try {
  reportFile = assertDisposableCachePath(
    options.jsonOut ?? join(reportDirectory, `run-${runId}.json`),
  );
} catch (error) {
  console.error(sanitizeError(error).message);
  process.exit(2);
}

let temporaryDirectory = null;
let cacheFile;
if (options.cache) {
  try {
    cacheFile = assertDisposableCachePath(options.cache);
  } catch (error) {
    console.error(sanitizeError(error).message);
    process.exit(2);
  }
  if (existsSync(cacheFile) && !options.reuseCache) {
    console.error(
      `Refusing to overwrite existing cache ${cacheFile}. Pass --reuse-cache only when that isolated cache is intentional.`,
    );
    process.exit(2);
  }
  mkdirSync(dirname(cacheFile), { recursive: true, mode: 0o700 });
} else {
  temporaryDirectory = mkdtempSync(
    join(tmpdir(), "m365-raw-http-auth-probe-"),
  );
  chmodSync(temporaryDirectory, 0o700);
  cacheFile = join(temporaryDirectory, "raw-oauth-cache.json");
}

if (resolve(reportFile) === resolve(cacheFile)) {
  console.error("--json-out and --cache must be different files.");
  process.exit(2);
}

const profileDirectory =
  options.browserProfile ??
  join(temporaryDirectory ?? dirname(cacheFile), "browser-profile");
const report = {
  audiences: {},
  completedAt: null,
  configuration: {
    audiences: options.audiences,
    authority: authorityDescriptor(options.authority),
    cache: options.cache ? "explicit-isolated" : "temporary",
    discoveryOnly: options.discoveryOnly,
    headlessBrowser: options.headlessBrowser,
    incrementalInteraction: options.incrementalInteraction,
    method: options.method,
    protocol: "oauth2-raw-http",
    prompt: options.prompt ?? null,
    silentOnly: options.silentOnly,
  },
  discovery: null,
  environment: {
    authLibrary: null,
    node: process.version,
    platform: `${process.platform}/${process.arch}`,
  },
  error: null,
  httpTrace: [],
  identity: null,
  runId,
  startedAt: new Date().toISOString(),
  status: "running",
};

console.log("Phase 0 enterprise M365 raw-HTTP OAuth probe");
console.log("  auth library=none");
console.log(`  method=${options.method}`);
console.log(`  authority=${options.authority}`);
console.log(`  audiences=${options.audiences.join(",")}`);
console.log("  cache=isolated (production credentials are never read or written)");
console.log("  M365 chat quota=0 messages\n");

try {
  const endpoints = await discoverEndpoints(options.authority, {
    timeoutMs: options.timeoutMs,
    trace: report.httpTrace,
  });
  report.discovery = {
    authorizationEndpointParsed: Boolean(endpoints.authorizationEndpoint),
    deviceAuthorizationEndpointParsed: Boolean(
      endpoints.deviceAuthorizationEndpoint,
    ),
    issuerPresent: Boolean(endpoints.issuer),
    tokenEndpointParsed: Boolean(endpoints.tokenEndpoint),
  };
  console.log("[discovery] raw OIDC GET + JSON parse: OK");

  if (options.discoveryOnly) {
    report.status = "succeeded";
    process.exitCode = 0;
    console.log("[discovery] stopped before authorization as requested.");
  } else {
    await runMatrix({
      cacheFile,
      endpoints,
      options,
      profileDirectory,
      report,
    });
    const failures = options.audiences.some(
      (audience) =>
        !report.audiences[audience]?.restartSilent?.ok &&
        !report.audiences[audience]?.silent?.ok,
    );
    report.status = failures ? "partial" : "succeeded";
    process.exitCode = failures ? 1 : 0;
  }
} catch (error) {
  report.error = sanitizeError(error);
  report.status = "failed";
  process.exitCode = 1;
  console.error(`\nProbe failed: ${report.error.message}`);
} finally {
  report.completedAt = new Date().toISOString();
  writeRedactedReport(reportFile, report);
  console.log(`\nRedacted report: ${reportFile}`);

  if (temporaryDirectory && !options.keepCache) {
    rmSync(temporaryDirectory, { force: true, recursive: true });
    console.log("Temporary raw refresh-token cache removed.");
  } else if (temporaryDirectory) {
    console.log(`Sensitive temporary cache retained at: ${cacheFile}`);
  }
}
