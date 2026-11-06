// WebAuthn in the browser: the server sends options with base64url fields; the browser
// API wants ArrayBuffers and returns them. Recent browsers convert themselves
// (parseCreationOptionsFromJSON / toJSON); the fallback does it by hand.
import { post } from './api'

const b64u = {
  dec: (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), (c) => c.charCodeAt(0)).buffer,
  enc: (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
}

type Json = Record<string, unknown>
const PKC = () => window.PublicKeyCredential as unknown as {
  parseCreationOptionsFromJSON?: (o: Json) => PublicKeyCredentialCreationOptions
  parseRequestOptionsFromJSON?: (o: Json) => PublicKeyCredentialRequestOptions
} | undefined

export const passkeySupported = () => typeof window !== 'undefined' && !!window.PublicKeyCredential && window.isSecureContext

function creationOptions(o: Json): PublicKeyCredentialCreationOptions {
  const f = PKC()?.parseCreationOptionsFromJSON
  if (f) return f(o)
  const user = o.user as Json
  return {
    ...(o as unknown as PublicKeyCredentialCreationOptions),
    challenge: b64u.dec(o.challenge as string),
    user: { ...(user as unknown as PublicKeyCredentialUserEntity), id: b64u.dec(user.id as string) },
    excludeCredentials: ((o.excludeCredentials as Json[] | undefined) ?? []).map((c) => ({ ...(c as unknown as PublicKeyCredentialDescriptor), id: b64u.dec(c.id as string) })),
  }
}

function requestOptions(o: Json): PublicKeyCredentialRequestOptions {
  const f = PKC()?.parseRequestOptionsFromJSON
  if (f) return f(o)
  return {
    ...(o as unknown as PublicKeyCredentialRequestOptions),
    challenge: b64u.dec(o.challenge as string),
    allowCredentials: ((o.allowCredentials as Json[] | undefined) ?? []).map((c) => ({ ...(c as unknown as PublicKeyCredentialDescriptor), id: b64u.dec(c.id as string) })),
  }
}

function toJSON(c: PublicKeyCredential): Json {
  const j = (c as unknown as { toJSON?: () => Json }).toJSON
  if (j) return j.call(c)
  const r = c.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse
  const response: Json = { clientDataJSON: b64u.enc(r.clientDataJSON) }
  if (r.attestationObject) {
    response.attestationObject = b64u.enc(r.attestationObject)
    response.transports = r.getTransports?.() ?? []
  }
  if (r.authenticatorData) {
    response.authenticatorData = b64u.enc(r.authenticatorData)
    response.signature = b64u.enc(r.signature)
    if (r.userHandle) response.userHandle = b64u.enc(r.userHandle)
  }
  return { id: c.id, rawId: b64u.enc(c.rawId), type: c.type, response, clientExtensionResults: c.getClientExtensionResults(), authenticatorAttachment: c.authenticatorAttachment }
}

const cancelled = (e: unknown) => e instanceof DOMException && (e.name === 'NotAllowedError' || e.name === 'AbortError')

// addPasskey registers a passkey for the signed-in user on this name.
export async function addPasskey(name: string) {
  const b = await post<{ flow: string; options: Json }>('/me/passkeys/begin', { name })
  let cred: PublicKeyCredential
  try {
    cred = await navigator.credentials.create({ publicKey: creationOptions(b.options) }) as PublicKeyCredential
  } catch (e) {
    throw new Error(cancelled(e) ? '已取消' : e instanceof DOMException && e.name === 'InvalidStateError' ? '这台设备已经有这个账号的 Passkey 了' : (e as Error).message)
  }
  return post(`/me/passkeys/finish?flow=${b.flow}`, toJSON(cred))
}

export function defaultPasskeyName() {
  const ua = navigator.userAgent
  if (/iPhone/.test(ua)) return 'iPhone'
  if (/iPad/.test(ua)) return 'iPad'
  if (/Android/.test(ua)) return 'Android 手机'
  if (/Macintosh/.test(ua)) return 'Mac'
  if (/Windows/.test(ua)) return 'Windows 电脑'
  return '我的设备'
}

async function assert(options: Json) {
  try {
    return await navigator.credentials.get({ publicKey: requestOptions(options) }) as PublicKeyCredential
  } catch (e) {
    throw new Error(cancelled(e) ? '已取消' : (e as Error).message)
  }
}

// verifyPasskey proves the signed-in user holds a passkey, before weakening a strict mode.
export async function verifyPasskey() {
  const b = await post<{ flow: string; options: Json }>('/me/reauth/begin', {})
  await post(`/me/reauth/finish?flow=${b.flow}`, toJSON(await assert(b.options)))
}

export interface SecondStep { second_step: true; flow: string; options: Json }

// finishSecondStep: the password was right; the passkey completes the sign-in.
export async function finishSecondStep(s: SecondStep, tz: string) {
  return post<{ user: unknown; csrf: string }>(`/login/passkey/finish?flow=${s.flow}&tz=${encodeURIComponent(tz)}`, toJSON(await assert(s.options)))
}

// passkeyLogin signs in with any passkey for this name (no username).
export async function passkeyLogin(tz: string) {
  const b = await post<{ flow: string; options: Json }>('/login/passkey/begin', {})
  return post<{ user: unknown; csrf: string }>(`/login/passkey/finish?flow=${b.flow}&tz=${encodeURIComponent(tz)}`, toJSON(await assert(b.options)))
}
