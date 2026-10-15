
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} from "npm:@simplewebauthn/server@14.0.3";
import { createClient } from "npm:@supabase/supabase-js@2.117.3";

const SITE_ORIGIN = "https://t08-passkey-intro.vercel.app";
const RP_ID = "t08-passkey-intro.vercel.app";
const DB_URL = Deno.env.get("SUPABASE_URL") || "";
const legacyKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
const newKeys = Deno.env.get("SUPABASE_SECRET_KEYS");
const SERVICE_KEY = legacyKey || (newKeys ? JSON.parse(newKeys)["default"] : "");
const db = createClient(DB_URL, SERVICE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});
const publicHeaders = {
  "Access-Control-Allow-Origin": SITE_ORIGIN,
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, content-type, apikey, x-client-info",
  "Cache-Control": "no-store",
  "Vary": "Origin",
  "X-Content-Type-Options": "nosniff",
};
function respond(status: number, payload: Record<string, unknown>) {
  return new Response(JSON.stringify(payload), {
    status, headers: { ...publicHeaders, "Content-Type": "application/json; charset=utf-8" },
  });
}
function error(status: number, code: string) { return respond(status, { ok: false, error: code }); }
function b64url(bytes: Uint8Array) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromB64url(s: string) {
  const norm = s.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(norm + "=".repeat((4 - norm.length % 4) % 4));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}
async function sha256(input: string) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input)));
  return Array.from(digest, (n) => n.toString(16).padStart(2, "0")).join("");
}
function extractBearer(req: Request) {
  const value = req.headers.get("Authorization") || "";
  return /^Bearer [A-Za-z0-9_-]{43,128}$/.test(value) ? value.slice(7) : null;
}
async function currentSession(req: Request) {
  const token = extractBearer(req);
  if (!token) return null;
  const hash = await sha256(token);
  const { data, error: dbError } = await db.from("t08_sessions")
    .select("token_hash,account_id,credential_id,expires_at,revoked_at")
    .eq("token_hash", hash).is("revoked_at", null)
    .gt("expires_at", new Date().toISOString()).maybeSingle();
  if (dbError || !data) return null;
  const { data: account } = await db.from("t08_accounts").select("id,alias")
    .eq("id", data.account_id).maybeSingle();
  return account ? { hash, account, credentialId: data.credential_id } : null;
}
async function createSession(accountId: string, credentialId: string) {
  const token = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const expiry = new Date(Date.now() + 30 * 60_000).toISOString();
  const { error: dbError } = await db.from("t08_sessions").insert({
    account_id: accountId, credential_id: credentialId,
    token_hash: await sha256(token), expires_at: expiry,
  });
  if (dbError) throw Error("session_insert_failed");
  return { token, expiresAt: expiry };
}
async function bodyOf(req: Request) {
  const contentLength = Number(req.headers.get("Content-Length") || 0);
  if (contentLength > 90_000) throw Error("request_too_large");
  const s = await req.text();
  if (s.length > 90_000) throw Error("request_too_large");
  return JSON.parse(s || "{}");
}
function aliasValid(x: unknown) { return typeof x === "string" && /^[a-zA-Z0-9_-]{3,24}$/.test(x); }
function nameValid(x: unknown) { return typeof x === "string" && x.trim().length > 0 && x.trim().length <= 60; }
const places = new Set(["device", "google", "security-key", "other"]);

async function handle(req: Request): Promise<Response> {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: publicHeaders });
  if (req.headers.get("Origin") && req.headers.get("Origin") !== SITE_ORIGIN) return error(403, "origin_not_allowed");
  const url = new URL(req.url);
  const op = (url.searchParams.get("op") || "health").trim();
  if (req.method === "GET" && op === "health") return respond(200, {
    ok: true, service: "t08-passkey", authentication: "WebAuthn",
    rpId: RP_ID, noPassword: true,
  });
  if (req.method === "GET") {
    const session = await currentSession(req);
    if (!session) return error(401, "authentication_required");
    if (op === "me") {
      const { data: usedKey, error: usedKeyError } = await db.from("t08_passkeys")
        .select("credential_id,name").eq("account_id",session.account.id)
        .eq("credential_id",session.credentialId).maybeSingle();
      if (usedKeyError || !usedKey) return error(401,"session_credential_removed");
      return respond(200, {
        ok: true, account: { id: session.account.id, alias: session.account.alias },
        authenticatedPasskey: { name:usedKey.name, credentialIdPrefix:usedKey.credential_id.slice(0,8) },
        sessionType: "opaque_bearer_token", sessionLifetimeMinutes: 30,
      });
    }
    if (op === "passkeys") {
      const { data, error: e } = await db.from("t08_passkeys")
        .select("credential_id,name,storage_place,created_at,device_type,backed_up")
        .eq("account_id", session.account.id).order("created_at", { ascending: true });
      if (e) return error(503, "db_read_failed");
      return respond(200, { ok: true, passkeys: data || [], lastPasskeyDeletion: "blocked" });
    }
    if (op === "private") {
      const requestedAccount = url.searchParams.get("account_id");
      const { data, error: e } = await db.from("t08_private_notes")
        .select("id,title,body,created_at").eq("account_id", session.account.id).order("id");
      if (e) return error(503, "db_read_failed");
      return respond(200, {
        ok: true, accountId: session.account.id,
        ignoredClaimedAccount: requestedAccount && requestedAccount !== session.account.id,
        notes: data || [],
      });
    }
    if (op === "private-for") {
      const requested = url.searchParams.get("account_id");
      if (!requested || requested !== session.account.id) return error(403, "cross_account_denied");
      const { data, error: e } = await db.from("t08_private_notes")
        .select("id,title,body").eq("account_id", session.account.id).order("id");
      if (e) return error(503, "db_read_failed");
      return respond(200, { ok: true, notes: data || [] });
    }
    return error(404, "unknown_route");
  }
  if (req.method !== "POST") return error(405, "method_not_allowed");
  let body: Record<string, any>;
  try { body = await bodyOf(req); } catch (_) { return error(400, "invalid_json"); }

  if (op === "register-options") {
    const session = await currentSession(req);
    const alias = session ? session.account.alias : body.alias;
    if (!aliasValid(alias) || !nameValid(body.passkeyName) || !places.has(body.storagePlace)) {
      return error(400, "invalid_registration_input");
    }
    let accountId = session?.account.id || crypto.randomUUID();
    let existing: any[] = [];
    if (!session) {
      const { data } = await db.from("t08_accounts").select("id").eq("alias", alias).maybeSingle();
      if (data) return error(409, "alias_already_registered");
    } else {
      const { data } = await db.from("t08_passkeys")
        .select("credential_id,transports").eq("account_id", accountId);
      existing = data || [];
    }
    const options = await generateRegistrationOptions({
      rpName: "ALEPH T08 Passkey Intro",
      rpID: RP_ID,
      userID: new TextEncoder().encode(accountId),
      userName: alias,
      userDisplayName: alias,
      attestationType: "none",
      preferredAuthenticatorType: ["remoteDevice","securityKey","localDevice"].includes(body.preferredAuthenticatorType)?body.preferredAuthenticatorType:undefined,
      excludeCredentials: existing.map(c => ({ id: c.credential_id, transports: c.transports || [] })),
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      supportedAlgorithmIDs: [-7, -257],
      timeout: 60_000,
    });
    const flowId = crypto.randomUUID();
    const { error: e } = await db.from("t08_challenges").insert({
      id: flowId, purpose: "register",
      account_id: accountId, account_alias: alias,
      challenge: options.challenge, is_new_account: !session,
      passkey_name: body.passkeyName.trim(), storage_place: body.storagePlace,
      expires_at: new Date(Date.now() + 5 * 60_000).toISOString(),
    });
    if (e) return error(503, "challenge_store_failed");
    return respond(200, { ok: true, flowId, options });
  }
  if (op === "register-cancel") {
    if (typeof body.flowId !== "string") return error(400, "flow_required");
    const { error: e } = await db.from("t08_challenges").update({ consumed_at: new Date().toISOString() })
      .eq("id", body.flowId).eq("purpose","register").is("consumed_at",null);
    if (e) return error(503, "challenge_cancel_failed");
    return respond(200, { ok: true, registration: "cancelled", credentialSaved: false });
  }
  if (op === "register-verify") {
    if (typeof body.flowId !== "string" || !body.response || typeof body.response.id !== "string") {
      return error(400, "invalid_attestation");
    }
    const { data, error: e } = await db.rpc("t08_take_challenge", {
      p_flow_id: body.flowId, p_purpose: "register",
    });
    if (e) return error(503,"challenge_store_failed");
    const flow = data?.[0];
    if (!flow) return error(409, "challenge_already_used_or_expired");
    if (!flow.is_new_account) {
      const session = await currentSession(req);
      if (!session || session.account.id !== flow.account_id) return error(401, "registration_auth_required");
    }
    let result;
    try {
      result = await verifyRegistrationResponse({
        response: body.response, expectedChallenge: flow.challenge,
        expectedOrigin: SITE_ORIGIN, expectedRPID: RP_ID,
        requireUserVerification: true,
        supportedAlgorithmIDs: [-7,-257],
      });
    } catch (_) { return error(400, "registration_signature_rejected"); }
    if (!result.verified || !result.registrationInfo) return error(403, "registration_unverified");
    const c = result.registrationInfo.credential;
    if (!c?.publicKey?.length) return error(400,"no_public_key");
    const { data: accountId, error: finalError } = await db.rpc("t08_finish_registration", {
      p_flow_id: body.flowId,
      p_credential_id: c.id,
      p_public_key: b64url(c.publicKey),
      p_counter: c.counter,
      p_transports: c.transports || [],
      p_device_type: result.registrationInfo.credentialDeviceType,
      p_backed_up: result.registrationInfo.credentialBackedUp,
    });
    if (finalError) return error(409, "credential_store_failed");
    const login = await createSession(accountId, c.id);
    return respond(201, { ok: true, registered: true,
      accountId, credentialId: c.id, stored: "public_key_only",
      ...login,
    });
  }
  if (op === "login-options") {
    if (!aliasValid(body.alias)) return error(400, "alias_required");
    const { data: user } = await db.from("t08_accounts").select("id,alias").eq("alias",body.alias).maybeSingle();
    if (!user) return error(404,"account_not_found");
    const { data: keys, error: e } = await db.from("t08_passkeys")
      .select("credential_id,transports").eq("account_id",user.id);
    if (e || !keys?.length) return error(403, "no_active_passkey");
    // An exact credential may be selected during an authenticated diagnostic.
    // The server still verifies every assertion cryptographically before issuing a session.
    const requestedCredential = body.targetCredentialId;
    if (requestedCredential !== undefined && (typeof requestedCredential !== "string" || !keys.some(k=>k.credential_id===requestedCredential))) {
      return error(403,"credential_not_registered");
    }
    const permittedKeys = requestedCredential ? keys.filter(k=>k.credential_id===requestedCredential) : keys;
    const options = await generateAuthenticationOptions({
      rpID: RP_ID, userVerification: "required", timeout: 60_000,
      allowCredentials: permittedKeys.map(k => ({ id:k.credential_id, transports: k.transports || [] })),
    });
    const flowId=crypto.randomUUID();
    const { error: storeErr } = await db.from("t08_challenges").insert({
      id:flowId,purpose:"login",account_id:user.id,account_alias:user.alias,
      challenge:options.challenge,
      expires_at:new Date(Date.now()+5*60_000).toISOString(),
    });
    if (storeErr) return error(503, "challenge_store_failed");
    return respond(200, { ok:true, flowId, options });
  }
  if (op === "login-verify") {
    if (typeof body.flowId !== "string" || !body.response || typeof body.response.id !== "string") {
      return error(400, "invalid_assertion");
    }
    const { data, error: e } = await db.rpc("t08_take_challenge", {
      p_flow_id: body.flowId, p_purpose:"login",
    });
    if (e) return error(503,"challenge_store_failed");
    const flow=data?.[0];
    if (!flow) return error(409,"challenge_already_used_or_expired");
    const { data:key, error:keyErr } = await db.from("t08_passkeys")
      .select("credential_id,account_id,public_key_b64url,counter,transports")
      .eq("credential_id",body.response.id).eq("account_id",flow.account_id).maybeSingle();
    if (keyErr || !key) return error(403,"credential_not_registered");
    let result;
    try {
      result = await verifyAuthenticationResponse({
        response: body.response, expectedChallenge:flow.challenge,
        expectedOrigin:SITE_ORIGIN,expectedRPID:RP_ID,
        credential:{
          id:key.credential_id,publicKey:fromB64url(key.public_key_b64url),
          counter:Number(key.counter),transports:key.transports || [],
        },
        requireUserVerification:true,
      });
    } catch (_) { return error(403, "invalid_signature"); }
    if (!result.verified) return error(403,"invalid_signature");
    const { data:updated, error:updateErr } = await db.from("t08_passkeys")
      .update({ counter: result.authenticationInfo.newCounter })
      .eq("credential_id",key.credential_id).eq("counter",key.counter)
      .select("credential_id").maybeSingle();
    if (updateErr || !updated) return error(409,"counter_conflict");
    const login=await createSession(flow.account_id,key.credential_id);
    return respond(200, {ok:true,verified:true,
      accountId:flow.account_id,authenticationMethod:"public_key_signature",
      ...login});
  }
  if (op === "logout") {
    const session=await currentSession(req);
    if (!session) return error(401,"authentication_required");
    const {error:e}=await db.from("t08_sessions").update({revoked_at:new Date().toISOString()})
      .eq("token_hash",session.hash).is("revoked_at",null);
    if(e) return error(503,"logout_failed");
    return respond(200,{ok:true,logout:true});
  }
  if (op === "delete-passkey") {
    const session=await currentSession(req);
    if (!session) return error(401,"authentication_required");
    const keyId=body.credentialId;
    if (typeof keyId!=="string"||!keyId) return error(400,"credential_id_required");
    const {data:owned}=await db.from("t08_passkeys")
      .select("credential_id").eq("account_id",session.account.id).eq("credential_id",keyId).maybeSingle();
    if(!owned) return error(403,"credential_not_owned");
    const {data:removed,error:e}=await db.rpc("t08_delete_passkey_safely",{
      p_account_id:session.account.id,p_credential_id:keyId,
    });
    if(e) return error(503,"delete_failed");
    if(!removed) return error(409,"last_passkey_cannot_be_deleted");
    await db.from("t08_sessions").update({revoked_at:new Date().toISOString()})
      .eq("account_id",session.account.id).eq("credential_id",keyId);
    return respond(200,{ok:true,deleted:true,deletedCredentialId:keyId});
  }
  return error(404,"unknown_route");
}
Deno.serve(async (req:Request) => {
  try {
    if (!DB_URL || !SERVICE_KEY) return error(503,"server_configuration_missing");
    return await handle(req);
  } catch (e) {
    // Never log tokens, passwords, assertions or private notes.
    console.error("T08 request failed:", String(e instanceof Error ? e.message : "internal_error").slice(0,140));
    return error(503, "service_unavailable");
  }
});
