import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

export const CLIENT_ID = "c0ab8ce9-e9a0-42e7-b064-33d422df41f1";
export const DEFAULT_AUTHORITY =
  "https://login.microsoftonline.com/organizations";
export const NATIVECLIENT_REDIRECT_URI =
  "https://login.microsoftonline.com/common/oauth2/nativeclient";

export const SCOPE_SETS = Object.freeze({
  chat: Object.freeze([
    "https://substrate.office.com/sydney/M365Chat.Read",
    "https://substrate.office.com/sydney/sydney.readwrite",
  ]),
  bap: Object.freeze(["https://api.bap.microsoft.com/.default"]),
  powerplatform: Object.freeze(["https://api.powerplatform.com/.default"]),
});

export const EXPECTED_AUDIENCES = Object.freeze({
  chat: Object.freeze(["https://substrate.office.com/sydney"]),
  bap: Object.freeze(["https://api.bap.microsoft.com"]),
  powerplatform: Object.freeze(["https://api.powerplatform.com"]),
});

const OIDC_SCOPES = Object.freeze(["openid", "profile", "offline_access"]);
const METHODS = new Set([
  "browser",
  "device-code",
  "nativeclient-browser",
]);
const METHOD_ALIASES = new Map([
  ["nativeclient-visible", "nativeclient-browser"],
]);
const PROMPTS = new Set(["none", "select_account", "login"]);
const BOOLEAN_OPTIONS = new Set([
  "allow-non-tty",
  "discovery-only",
  "execute",
  "headless-browser",
  "help",
  "incremental-interaction",
  "keep-cache",
  "no-open",
  "reuse-cache",
  "show-http",
  "silent-only",
]);
const VALUE_OPTIONS = new Set([
  "audiences",
  "authority",
  "browser-profile",
  "cache",
  "chromium",
  "json-out",
  "login-hint",
  "method",
  "prompt",
  "timeout",
]);

export class OAuthProtocolError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "OAuthProtocolError";
    this.oauthError = details.oauthError ?? null;
    this.errorCodes = details.errorCodes ?? [];
    this.correlationId = details.correlationId ?? null;
    this.statusCode = details.statusCode ?? null;
    this.subError = details.subError ?? null;
  }
}

export function normalizeAuthority(value) {
  const authority = String(value || "organizations").trim();
  const absolute = authority.match(
    /^https:\/\/login\.microsoftonline\.com\/([^/?#]+?)(?:\/v2\.0)?\/?$/i,
  );
  if (absolute) {
    return `https://login.microsoftonline.com/${absolute[1]}`;
  }
  if (/^[a-z0-9.-]+$/i.test(authority)) {
    return `https://login.microsoftonline.com/${authority}`;
  }
  throw new Error(
    "--authority must be organizations, common, a tenant ID/domain, or a login.microsoftonline.com authority URL",
  );
}

export function authorityDescriptor(authority) {
  const normalized = normalizeAuthority(authority);
  const tenant = new URL(normalized).pathname.split("/").filter(Boolean)[0];
  if (["common", "organizations", "consumers"].includes(tenant)) {
    return tenant;
  }
  return "tenant-specific";
}

function takeOptionValue(argv, index, name, inlineValue) {
  if (inlineValue !== undefined) return { value: inlineValue, nextIndex: index };
  const next = argv[index + 1];
  if (!next || next.startsWith("--")) {
    throw new Error(`--${name} requires a value`);
  }
  return { value: next, nextIndex: index + 1 };
}

export function parseArgs(argv) {
  const raw = {};

  for (let index = 0; index < argv.length; index++) {
    const token = argv[index];
    if (token === "--") continue;
    if (!token.startsWith("--")) {
      throw new Error(`Unexpected positional argument: ${token}`);
    }

    const match = token.match(/^--([^=]+)(?:=(.*))?$/);
    const name = match?.[1];
    const inlineValue = match?.[2];
    if (!name || (!BOOLEAN_OPTIONS.has(name) && !VALUE_OPTIONS.has(name))) {
      throw new Error(`Unknown option: ${token}`);
    }

    if (BOOLEAN_OPTIONS.has(name)) {
      if (inlineValue !== undefined) {
        throw new Error(`--${name} is a flag and does not take a value`);
      }
      raw[name] = true;
      continue;
    }

    const { value, nextIndex } = takeOptionValue(
      argv,
      index,
      name,
      inlineValue,
    );
    raw[name] = value;
    index = nextIndex;
  }

  const requestedMethod = raw.method ?? "browser";
  const method = METHOD_ALIASES.get(requestedMethod) ?? requestedMethod;
  if (!METHODS.has(method)) {
    throw new Error(`--method must be one of: ${[...METHODS].join(", ")}`);
  }

  const prompt = raw.prompt ?? "select_account";
  if (!PROMPTS.has(prompt)) {
    throw new Error(`--prompt must be one of: ${[...PROMPTS].join(", ")}`);
  }

  const audiences = String(raw.audiences ?? "chat,bap,powerplatform")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  const uniqueAudiences = [...new Set(audiences)];
  if (uniqueAudiences.length === 0) {
    throw new Error("--audiences must include at least one audience");
  }
  for (const audience of uniqueAudiences) {
    if (!(audience in SCOPE_SETS)) {
      throw new Error(
        `Unknown audience '${audience}'. Use: ${Object.keys(SCOPE_SETS).join(", ")}`,
      );
    }
  }

  const timeoutSeconds = Number(raw.timeout ?? 180);
  if (
    !Number.isInteger(timeoutSeconds) ||
    timeoutSeconds < 30 ||
    timeoutSeconds > 900
  ) {
    throw new Error("--timeout must be an integer from 30 through 900 seconds");
  }

  return {
    allowNonTty: Boolean(raw["allow-non-tty"]),
    audiences: uniqueAudiences,
    authority: normalizeAuthority(raw.authority),
    browserProfile: raw["browser-profile"]
      ? resolve(String(raw["browser-profile"]))
      : null,
    cache: raw.cache ? resolve(String(raw.cache)) : null,
    chromium: raw.chromium ? resolve(String(raw.chromium)) : null,
    discoveryOnly: Boolean(raw["discovery-only"]),
    execute: Boolean(raw.execute),
    headlessBrowser: Boolean(raw["headless-browser"]),
    help: Boolean(raw.help),
    incrementalInteraction: Boolean(raw["incremental-interaction"]),
    jsonOut: raw["json-out"] ? resolve(String(raw["json-out"])) : null,
    keepCache: Boolean(raw["keep-cache"]),
    loginHint: raw["login-hint"] ? String(raw["login-hint"]) : null,
    method,
    noOpen: Boolean(raw["no-open"]),
    prompt: prompt === "none" ? undefined : prompt,
    reuseCache: Boolean(raw["reuse-cache"]),
    showHttp: Boolean(raw["show-http"]),
    silentOnly: Boolean(raw["silent-only"]),
    timeoutMs: timeoutSeconds * 1000,
  };
}

function canonicalPath(path) {
  let existingAncestor = resolve(path);
  const missingSegments = [];
  while (!existsSync(existingAncestor)) {
    const parent = dirname(existingAncestor);
    if (parent === existingAncestor) break;
    missingSegments.unshift(basename(existingAncestor));
    existingAncestor = parent;
  }
  const realAncestor = existsSync(existingAncestor)
    ? realpathSync(existingAncestor)
    : existingAncestor;
  return resolve(join(realAncestor, ...missingSegments));
}

export function productionCredentialPaths(home = homedir()) {
  const directory = resolve(home, ".config", "opencode-m365");
  return [
    resolve(directory, "msal-cache.json"),
    resolve(directory, "secrets.json"),
  ];
}

export function assertDisposableCachePath(cacheFile, home = homedir()) {
  const candidate = canonicalPath(cacheFile);
  const productionPaths = productionCredentialPaths(home).map(canonicalPath);
  if (productionPaths.includes(candidate)) {
    throw new Error(
      `Refusing to use a production credential/cache file (${candidate}). Omit --cache for an isolated temporary raw-OAuth cache.`,
    );
  }
  return candidate;
}

function ensurePrivateDirectory(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  try {
    chmodSync(path, 0o700);
  } catch {
    // Windows does not implement POSIX file modes in the same way.
  }
}

function atomicWrite(path, data, mode = 0o600) {
  ensurePrivateDirectory(dirname(path));
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(temporary, data, { encoding: "utf8", mode });
  try {
    chmodSync(temporary, mode);
  } catch {
    // Best effort on non-POSIX platforms.
  }
  renameSync(temporary, path);
  try {
    chmodSync(path, mode);
  } catch {
    // Best effort on non-POSIX platforms.
  }
}

export function writeRawTokenCache(path, cache) {
  if (
    cache?.version !== 1 ||
    cache?.protocol !== "oauth2-raw-http" ||
    typeof cache?.refreshToken !== "string" ||
    !cache.refreshToken
  ) {
    throw new Error("Refusing to write an invalid raw OAuth cache");
  }
  atomicWrite(resolve(path), `${JSON.stringify(cache, null, 2)}\n`);
}

export function readRawTokenCache(path) {
  const cache = JSON.parse(readFileSync(resolve(path), "utf8"));
  if (
    cache?.version !== 1 ||
    cache?.protocol !== "oauth2-raw-http" ||
    typeof cache?.refreshToken !== "string" ||
    !cache.refreshToken ||
    typeof cache?.authority !== "string" ||
    typeof cache?.accountFingerprint !== "string"
  ) {
    throw new Error("The isolated raw OAuth cache has an invalid format");
  }
  return cache;
}

export function writeRedactedReport(path, report) {
  atomicWrite(resolve(path), `${JSON.stringify(report, null, 2)}\n`);
}

function decodeJwtPayload(token) {
  const segment = String(token ?? "").split(".")[1];
  if (!segment) throw new Error("Token is not a JWT");
  const padded = segment + "=".repeat((4 - (segment.length % 4)) % 4);
  return JSON.parse(
    Buffer.from(
      padded.replace(/-/g, "+").replace(/_/g, "/"),
      "base64",
    ).toString("utf8"),
  );
}

function decodeJwtPayloadOrNull(token) {
  try {
    return decodeJwtPayload(token);
  } catch {
    return null;
  }
}

function maskUsername(username) {
  if (!username) return null;
  const [local, domain] = String(username).split("@");
  if (!domain) return "<redacted>";
  return `${local.slice(0, 1) || "*"}***@${domain}`;
}

function shortIdentifier(value) {
  return value ? `${String(value).slice(0, 8)}…` : null;
}

function stableFingerprint(...values) {
  return createHash("sha256")
    .update(values.map((value) => String(value ?? "")).join("\u0000"))
    .digest("hex");
}

export function tokenIdentity(tokenResponse) {
  const accessClaims = decodeJwtPayloadOrNull(tokenResponse?.access_token);
  const idClaims = decodeJwtPayloadOrNull(tokenResponse?.id_token);
  const tenantId = accessClaims?.tid ?? idClaims?.tid;
  const objectId =
    accessClaims?.oid ?? idClaims?.oid ?? idClaims?.sub ?? accessClaims?.sub;
  if (!tenantId || !objectId) {
    throw new Error(
      "Token response did not expose a tenant-backed account identity (tid + oid/sub)",
    );
  }
  return {
    fingerprint: stableFingerprint(tenantId, objectId),
    objectId,
    tenantId,
    username:
      idClaims?.preferred_username ??
      idClaims?.upn ??
      accessClaims?.preferred_username ??
      accessClaims?.upn ??
      null,
  };
}

export function assertIdTokenNonce(tokenResponse, expectedNonce) {
  const idClaims = decodeJwtPayloadOrNull(tokenResponse?.id_token);
  if (!idClaims) {
    throw new Error("Authorization-code response returned no parseable id_token");
  }
  if (idClaims.nonce !== expectedNonce) {
    throw new Error("Microsoft id_token nonce mismatch");
  }
}

function normalizeAudience(value) {
  return String(value ?? "").replace(/\/+$/, "").toLowerCase();
}

export function tokenSummary(tokenResponse, options = {}) {
  const accessToken = String(tokenResponse?.access_token ?? "");
  const accessClaims = decodeJwtPayloadOrNull(accessToken);
  const idClaims = decodeJwtPayloadOrNull(tokenResponse?.id_token);
  let identity = null;
  try {
    identity = tokenIdentity(tokenResponse);
  } catch {
    // Some Microsoft resource tokens are intentionally opaque. The report records
    // that parsing was unavailable without retaining the token.
  }

  const expectedAudiences = options.audience
    ? EXPECTED_AUDIENCES[options.audience] ?? []
    : [];
  const observedAudience = accessClaims?.aud ?? null;
  const audienceMatchesExpected =
    observedAudience && expectedAudiences.length > 0
      ? expectedAudiences
          .map(normalizeAudience)
          .includes(normalizeAudience(observedAudience))
      : null;
  const scopes = String(accessClaims?.scp ?? tokenResponse?.scope ?? "")
    .split(/\s+/)
    .filter(Boolean)
    .sort();
  const expiresIn = Number(tokenResponse?.expires_in);

  return {
    account: identity
      ? {
          fingerprint: `${identity.fingerprint.slice(0, 12)}…`,
          objectId: shortIdentifier(identity.objectId),
          tenantId: shortIdentifier(identity.tenantId),
          username: maskUsername(identity.username),
        }
      : null,
    audience: observedAudience,
    audienceMatchesExpected,
    authorizedParty: accessClaims?.azp ?? accessClaims?.appid ?? null,
    enterpriseTenantBacked: Boolean(identity?.tenantId),
    expiresAt: Number.isFinite(expiresIn)
      ? new Date((options.now ?? Date.now()) + expiresIn * 1000).toISOString()
      : null,
    jwtParsed: Boolean(accessClaims),
    refreshTokenReceived: Boolean(tokenResponse?.refresh_token),
    scopes,
    tokenLength: accessToken.length,
    tokenType: tokenResponse?.token_type ?? null,
  };
}

export function sanitizeError(error) {
  const rawMessage = String(error?.message ?? error ?? "Unknown error");
  const message = rawMessage
    .replace(
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
      "<redacted-email>",
    )
    .replace(
      /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]*)?\b/g,
      "<redacted-jwt>",
    )
    .replace(
      /((?:[?&]|\b)(?:code|client_info|id_token|access_token|refresh_token|device_code|user_code|code_verifier)=)[^&\s]+/gi,
      "$1<redacted>",
    )
    .replace(
      /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
      "<redacted-guid>",
    )
    .replace(
      /\b[a-z0-9.-]+\.onmicrosoft\.com\b/gi,
      "<redacted-tenant-domain>",
    );

  return {
    code: error?.oauthError ?? error?.errorCode ?? error?.code ?? null,
    correlationId: shortIdentifier(error?.correlationId),
    errorCodes: Array.isArray(error?.errorCodes) ? error.errorCodes : [],
    message,
    name: error?.name ?? "Error",
    statusCode: error?.statusCode ?? null,
    subError: error?.subError ?? null,
  };
}

export function requestScopesForAudience(audience) {
  if (!(audience in SCOPE_SETS)) {
    throw new Error(`Unknown audience: ${audience}`);
  }
  return [...SCOPE_SETS[audience], ...OIDC_SCOPES];
}

export function generatePkce() {
  const verifier = randomBytes(64).toString("base64url");
  const challenge = createHash("sha256")
    .update(verifier)
    .digest("base64url");
  return { challenge, verifier };
}

export function randomOAuthValue() {
  return randomBytes(32).toString("base64url");
}

function assertMicrosoftIdentityUrl(value, label) {
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    url.hostname.toLowerCase() !== "login.microsoftonline.com" ||
    url.username ||
    url.password
  ) {
    throw new Error(`${label} is not a Microsoft Entra HTTPS endpoint`);
  }
  return url.toString();
}

function redactUrl(value) {
  const url = new URL(value);
  const queryFields = [...url.searchParams.keys()].sort();
  const pathSegments = url.pathname.split("/");
  const tenant = pathSegments[1]?.toLowerCase();
  if (
    tenant &&
    !["common", "organizations", "consumers"].includes(tenant)
  ) {
    pathSegments[1] = "<tenant>";
  }
  const redacted = `${url.origin}${pathSegments.join("/")}`
    .replace(
      /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
      "<redacted-guid>",
    );
  return { queryFields, url: redacted };
}

export function recordBrowserAuthorization(trace, url, transport) {
  const redacted = redactUrl(url);
  trace.push({
    method: "GET",
    queryFields: redacted.queryFields,
    requestFields: [],
    responseFields: [],
    status: null,
    step: "authorization-user-agent",
    transport,
    url: redacted.url,
  });
}

export async function requestJson({
  fetchImpl = globalThis.fetch,
  form,
  method = "GET",
  step,
  timeoutMs = 30_000,
  trace = [],
  url,
}) {
  if (typeof fetchImpl !== "function") {
    throw new Error("This Node.js runtime does not provide fetch()");
  }
  const endpoint = assertMicrosoftIdentityUrl(url, step);
  const headers = {
    accept: "application/json",
  };
  let body;
  let requestFields = [];
  if (form) {
    const parameters = new URLSearchParams(form);
    body = parameters.toString();
    headers["content-type"] = "application/x-www-form-urlencoded";
    requestFields = [...parameters.keys()].sort();
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const startedAt = Date.now();
  try {
    let currentEndpoint = endpoint;
    let response;
    for (let redirectCount = 0; redirectCount <= 3; redirectCount++) {
      response = await fetchImpl(currentEndpoint, {
        body,
        headers,
        method,
        redirect: "manual",
        signal: controller.signal,
      });
      const canPreserveRequest =
        response.status === 307 ||
        response.status === 308 ||
        (method === "GET" &&
          (response.status === 301 || response.status === 302));
      const location = response.headers?.get?.("location");
      if (!canPreserveRequest || !location) break;
      if (redirectCount === 3) {
        throw new Error(`${step} exceeded three Microsoft redirects`);
      }

      const redactedRedirect = redactUrl(currentEndpoint);
      trace.push({
        durationMs: Date.now() - startedAt,
        method,
        oauthError: null,
        queryFields: redactedRedirect.queryFields,
        requestFields,
        responseFields: [],
        status: response.status,
        step: `${step}-redirect`,
        transport: "raw-fetch",
        url: redactedRedirect.url,
      });
      await response.body?.cancel?.();
      currentEndpoint = assertMicrosoftIdentityUrl(
        new URL(location, currentEndpoint).toString(),
        `${step} redirect`,
      );
    }
    if (!response) throw new Error(`${step} returned no HTTP response`);
    const text = await response.text();
    if (text.length > 1_048_576) {
      throw new Error(`${step} returned more than 1 MiB`);
    }
    let payload;
    try {
      payload = text ? JSON.parse(text) : {};
    } catch {
      throw new Error(`${step} returned invalid JSON`);
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new Error(`${step} returned a non-object JSON payload`);
    }
    const redacted = redactUrl(currentEndpoint);
    trace.push({
      durationMs: Date.now() - startedAt,
      method,
      oauthError:
        typeof payload.error === "string" ? payload.error : null,
      queryFields: redacted.queryFields,
      requestFields,
      responseFields: Object.keys(payload).sort(),
      status: response.status,
      step,
      transport: "raw-fetch",
      url: redacted.url,
    });
    return {
      ok: response.ok,
      payload,
      status: response.status,
    };
  } catch (error) {
    const redacted = redactUrl(endpoint);
    trace.push({
      durationMs: Date.now() - startedAt,
      error: sanitizeError(error),
      method,
      queryFields: redacted.queryFields,
      requestFields,
      responseFields: [],
      status: null,
      step,
      transport: "raw-fetch",
      url: redacted.url,
    });
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function oauthFailure(step, result) {
  const payload = result?.payload ?? {};
  const oauthError =
    typeof payload.error === "string" ? payload.error : "oauth_error";
  const description =
    typeof payload.error_description === "string"
      ? payload.error_description
      : `${step} failed`;
  return new OAuthProtocolError(`${oauthError}: ${description}`, {
    correlationId: payload.correlation_id,
    errorCodes: payload.error_codes,
    oauthError,
    statusCode: result?.status,
    subError: payload.suberror,
  });
}

function assertSuccessfulToken(step, result) {
  if (!result.ok || result.payload?.error) {
    throw oauthFailure(step, result);
  }
  if (
    typeof result.payload?.access_token !== "string" ||
    !result.payload.access_token
  ) {
    throw new OAuthProtocolError(`${step} returned no access_token`, {
      statusCode: result.status,
    });
  }
  return result.payload;
}

export async function discoverEndpoints(
  authority,
  { fetchImpl, timeoutMs, trace = [] } = {},
) {
  const normalized = normalizeAuthority(authority);
  const discoveryUrl = `${normalized}/v2.0/.well-known/openid-configuration`;
  const result = await requestJson({
    fetchImpl,
    step: "oidc-discovery",
    timeoutMs,
    trace,
    url: discoveryUrl,
  });
  if (!result.ok) throw oauthFailure("oidc-discovery", result);

  const authorizationEndpoint = assertMicrosoftIdentityUrl(
    result.payload.authorization_endpoint,
    "authorization_endpoint",
  );
  const tokenEndpoint = assertMicrosoftIdentityUrl(
    result.payload.token_endpoint,
    "token_endpoint",
  );
  const deviceAuthorizationEndpoint = assertMicrosoftIdentityUrl(
    result.payload.device_authorization_endpoint ??
      `${normalized}/oauth2/v2.0/devicecode`,
    "device_authorization_endpoint",
  );
  return {
    authorizationEndpoint,
    deviceAuthorizationEndpoint,
    issuer: result.payload.issuer ?? null,
    tokenEndpoint,
  };
}

export function buildAuthorizationUrl({
  authorizationEndpoint,
  challenge,
  clientId = CLIENT_ID,
  loginHint,
  nonce,
  prompt,
  redirectUri,
  scopes,
  state,
}) {
  const url = new URL(
    assertMicrosoftIdentityUrl(
      authorizationEndpoint,
      "authorization_endpoint",
    ),
  );
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_mode", "query");
  url.searchParams.set("scope", scopes.join(" "));
  url.searchParams.set("state", state);
  url.searchParams.set("nonce", nonce);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  if (prompt) url.searchParams.set("prompt", prompt);
  if (loginHint) url.searchParams.set("login_hint", loginHint);
  return url.toString();
}

export async function exchangeAuthorizationCode({
  clientId = CLIENT_ID,
  code,
  fetchImpl,
  redirectUri,
  scopes,
  timeoutMs,
  tokenEndpoint,
  trace,
  verifier,
}) {
  const result = await requestJson({
    fetchImpl,
    form: {
      client_id: clientId,
      code,
      code_verifier: verifier,
      grant_type: "authorization_code",
      redirect_uri: redirectUri,
      scope: scopes.join(" "),
    },
    method: "POST",
    step: "authorization-code-token",
    timeoutMs,
    trace,
    url: tokenEndpoint,
  });
  return assertSuccessfulToken("authorization-code-token", result);
}

export async function refreshAccessToken({
  clientId = CLIENT_ID,
  fetchImpl,
  refreshToken,
  scopes,
  timeoutMs,
  tokenEndpoint,
  trace,
}) {
  const result = await requestJson({
    fetchImpl,
    form: {
      client_id: clientId,
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      scope: scopes.join(" "),
    },
    method: "POST",
    step: "refresh-token",
    timeoutMs,
    trace,
    url: tokenEndpoint,
  });
  return assertSuccessfulToken("refresh-token", result);
}

export async function requestDeviceAuthorization({
  clientId = CLIENT_ID,
  deviceAuthorizationEndpoint,
  fetchImpl,
  scopes,
  timeoutMs,
  trace,
}) {
  const result = await requestJson({
    fetchImpl,
    form: {
      client_id: clientId,
      scope: scopes.join(" "),
    },
    method: "POST",
    step: "device-authorization",
    timeoutMs,
    trace,
    url: deviceAuthorizationEndpoint,
  });
  if (!result.ok || result.payload?.error) {
    throw oauthFailure("device-authorization", result);
  }
  const payload = result.payload;
  if (
    typeof payload.device_code !== "string" ||
    typeof payload.user_code !== "string" ||
    typeof payload.verification_uri !== "string"
  ) {
    throw new OAuthProtocolError(
      "device-authorization returned an incomplete response",
      { statusCode: result.status },
    );
  }
  return payload;
}

const defaultSleep = (durationMs) =>
  new Promise((resolveSleep) => setTimeout(resolveSleep, durationMs));

export async function pollDeviceToken({
  clientId = CLIENT_ID,
  deviceAuthorization,
  fetchImpl,
  now = Date.now,
  sleep = defaultSleep,
  timeoutMs,
  tokenEndpoint,
  trace,
}) {
  const startedAt = now();
  const expiresInMs =
    Number(deviceAuthorization.expires_in || 900) * 1000;
  const deadline = startedAt + Math.min(timeoutMs, expiresInMs);
  let intervalMs = Math.max(
    1_000,
    Number(deviceAuthorization.interval || 5) * 1000,
  );

  while (now() < deadline) {
    await sleep(intervalMs);
    const result = await requestJson({
      fetchImpl,
      form: {
        client_id: clientId,
        device_code: deviceAuthorization.device_code,
        grant_type:
          "urn:ietf:params:oauth:grant-type:device_code",
      },
      method: "POST",
      step: "device-token-poll",
      timeoutMs: Math.min(30_000, timeoutMs),
      trace,
      url: tokenEndpoint,
    });
    if (result.ok && !result.payload?.error) {
      return assertSuccessfulToken("device-token-poll", result);
    }

    const oauthError = result.payload?.error;
    if (oauthError === "authorization_pending") continue;
    if (oauthError === "slow_down") {
      intervalMs += 5_000;
      continue;
    }
    throw oauthFailure("device-token-poll", result);
  }

  throw new OAuthProtocolError(
    `device-token-poll timed out after ${Math.round(timeoutMs / 1000)}s`,
    { oauthError: "expired_token" },
  );
}

export function createRawTokenCache({
  authority,
  previousCache,
  tokenResponse,
}) {
  const identity = tokenIdentity(tokenResponse);
  const refreshToken =
    tokenResponse.refresh_token ?? previousCache?.refreshToken;
  if (!refreshToken) {
    throw new Error(
      "Microsoft returned no refresh token; offline_access may be unavailable for this client/tenant",
    );
  }
  if (
    previousCache?.accountFingerprint &&
    previousCache.accountFingerprint !== identity.fingerprint
  ) {
    throw new Error(
      "Token acquisition switched account or tenant during the raw HTTP matrix",
    );
  }
  return {
    accountFingerprint: identity.fingerprint,
    authority: normalizeAuthority(authority),
    clientId: CLIENT_ID,
    protocol: "oauth2-raw-http",
    refreshToken,
    updatedAt: new Date().toISOString(),
    version: 1,
  };
}

export function assertSameIdentity(expectedFingerprint, tokenResponse) {
  const actual = tokenIdentity(tokenResponse);
  if (expectedFingerprint !== actual.fingerprint) {
    throw new Error(
      "Token acquisition switched account or tenant during the raw HTTP matrix",
    );
  }
  return actual;
}

export function buildDryRunPlan(options) {
  const steps = [
    "GET the tenant OIDC discovery document and parse Microsoft endpoints.",
  ];
  if (options.discoveryOnly) {
    steps.push(
      "Write the redacted HTTP metadata trace and stop before authorization.",
    );
    return steps;
  }
  if (options.silentOnly) {
    steps.push("Load the explicitly supplied isolated raw refresh-token cache.");
    for (const audience of options.audiences) {
      steps.push(
        `POST a refresh_token grant for ${audience} and parse the token response.`,
      );
    }
  } else {
    const first = options.audiences[0];
    if (options.method === "device-code") {
      steps.push(
        `POST a device authorization request for ${first}, then poll the token endpoint.`,
      );
    } else {
      steps.push(
        `Generate PKCE/state/nonce, open a user-controlled ${options.method} authorization request for ${first}, then capture the code.`,
      );
      steps.push(
        `POST the authorization code + PKCE verifier to the token endpoint for ${first}.`,
      );
    }
    steps.push(
      `Persist only the isolated refresh-token state, recreate the client state, and POST a refresh grant for ${first}.`,
    );
    for (const audience of options.audiences.slice(1)) {
      steps.push(`POST a refresh_token grant for ${audience}.`);
      if (options.incrementalInteraction) {
        steps.push(
          `If consent is required, repeat the user-driven raw OAuth flow for ${audience}.`,
        );
      }
    }
  }
  steps.push(
    "Write an HTTP metadata trace and redacted token summaries; never write tokens or auth codes to the report.",
  );
  return steps;
}

function readableForm(fields) {
  return Object.entries(fields)
    .map(([name, value]) => `  ${name}=${value}`)
    .join("\n");
}

export function buildHttpTemplates(options) {
  const authority = normalizeAuthority(options.authority);
  const templates = [
    `GET ${authority}/v2.0/.well-known/openid-configuration`,
  ];
  if (options.discoveryOnly) return templates;

  const firstAudience = options.audiences[0];
  const firstScopes = requestScopesForAudience(firstAudience).join(" ");
  if (!options.silentOnly) {
    if (options.method === "device-code") {
      templates.push(
        `POST ${authority}/oauth2/v2.0/devicecode\nContent-Type: application/x-www-form-urlencoded\n${readableForm({
          client_id: CLIENT_ID,
          scope: firstScopes,
        })}`,
      );
      templates.push(
        `POST ${authority}/oauth2/v2.0/token\nContent-Type: application/x-www-form-urlencoded\n${readableForm({
          client_id: CLIENT_ID,
          device_code: "<device-code>",
          grant_type:
            "urn:ietf:params:oauth:grant-type:device_code",
        })}`,
      );
    } else {
      const redirectUri =
        options.method === "nativeclient-browser"
          ? NATIVECLIENT_REDIRECT_URI
          : "http://localhost:<ephemeral-port>";
      templates.push(
        `GET ${authority}/oauth2/v2.0/authorize\n${readableForm({
          client_id: CLIENT_ID,
          code_challenge: "<generated-S256-challenge>",
          code_challenge_method: "S256",
          login_hint: options.loginHint ? "<redacted-login-hint>" : "<omitted>",
          nonce: "<generated-nonce>",
          prompt: options.prompt ?? "<omitted>",
          redirect_uri: redirectUri,
          response_mode: "query",
          response_type: "code",
          scope: firstScopes,
          state: "<generated-state>",
        })}`,
      );
      templates.push(
        `POST ${authority}/oauth2/v2.0/token\nContent-Type: application/x-www-form-urlencoded\n${readableForm({
          client_id: CLIENT_ID,
          code: "<authorization-code>",
          code_verifier: "<generated-PKCE-verifier>",
          grant_type: "authorization_code",
          redirect_uri: redirectUri,
          scope: firstScopes,
        })}`,
      );
    }
  }

  for (const audience of options.audiences) {
    templates.push(
      `POST ${authority}/oauth2/v2.0/token\nContent-Type: application/x-www-form-urlencoded\n${readableForm({
        client_id: CLIENT_ID,
        grant_type: "refresh_token",
        refresh_token: "<redacted-refresh-token>",
        scope: requestScopesForAudience(audience).join(" "),
      })}`,
    );
  }
  return templates;
}

export class LoopbackReceiver {
  constructor(timeoutMs, expectedState) {
    this.timeoutMs = timeoutMs;
    this.expectedState = expectedState;
    this.server = null;
    this.timer = null;
    this.responsePromise = null;
    this.resolveResponse = null;
    this.rejectResponse = null;
  }

  async start() {
    if (this.server) throw new Error("Loopback receiver already started");
    this.responsePromise = new Promise((resolveResponse, rejectResponse) => {
      this.resolveResponse = resolveResponse;
      this.rejectResponse = rejectResponse;
    });

    this.server = createServer((request, response) => {
      try {
        if (!request.url) throw new Error("Missing loopback request URL");
        const parsed = new URL(request.url, this.getRedirectUri());
        const state = parsed.searchParams.get("state");
        const code = parsed.searchParams.get("code");
        const oauthError = parsed.searchParams.get("error");

        if (!code && !oauthError) {
          response.statusCode = 404;
          response.end("Waiting for Microsoft authorization.");
          return;
        }
        if (state !== this.expectedState) {
          response.statusCode = 400;
          response.end("Authorization state mismatch. Return to the terminal.");
          this.finish(new Error("Microsoft authorization state mismatch"));
          return;
        }

        response.statusCode = oauthError ? 400 : 200;
        response.setHeader("content-type", "text/plain; charset=utf-8");
        response.end(
          oauthError
            ? "Microsoft authorization failed. Return to the terminal."
            : "Microsoft authorization completed. You can close this window.",
        );
        this.finish(null, Object.fromEntries(parsed.searchParams.entries()));
      } catch (error) {
        response.statusCode = 400;
        response.end("Invalid Microsoft authorization response.");
        this.finish(error);
      }
    });

    await new Promise((resolveListen, rejectListen) => {
      this.server.once("error", rejectListen);
      this.server.listen(0, "127.0.0.1", resolveListen);
    });
    this.timer = setTimeout(() => {
      this.finish(
        new Error(
          `System-browser authorization timed out after ${this.timeoutMs / 1000}s`,
        ),
      );
    }, this.timeoutMs);
    this.timer.unref?.();
    return this.getRedirectUri();
  }

  getRedirectUri() {
    if (!this.server?.listening) {
      throw new Error("Loopback receiver is not listening");
    }
    const address = this.server.address();
    if (!address || typeof address === "string") {
      throw new Error("Loopback receiver returned an invalid address");
    }
    return `http://localhost:${address.port}`;
  }

  waitForResponse() {
    if (!this.responsePromise) {
      throw new Error("Loopback receiver has not started");
    }
    return this.responsePromise;
  }

  finish(error, value) {
    if (!this.responsePromise) return;
    const resolveResponse = this.resolveResponse;
    const rejectResponse = this.rejectResponse;
    this.responsePromise = null;
    this.resolveResponse = null;
    this.rejectResponse = null;
    this.close();
    if (error) rejectResponse(error);
    else resolveResponse(value);
  }

  close() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    if (!this.server) return;
    this.server.close();
    this.server.unref();
    this.server = null;
  }
}
