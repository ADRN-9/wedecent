export const ROUTE_AUTHORIZATION_VERSION = 1
export const ROUTE_AUTHORIZATION_ISSUER = 'wedecent-control-plane'
export const ROUTE_AUTHORIZATION_AUDIENCE = 'wedecent-mesh-router'
export const ROUTE_AUTHORIZATION_PERMISSION = 'mesh.forward'
export const ROUTE_AUTHORIZATION_DOMAIN = 'wedecent-mesh-forward-v1'
export const MAX_ROUTE_AUTHORIZATION_LIFETIME_MS = 120_000
export const MAX_ROUTE_AUTHORIZATION_COST = 1_000_000_000

const deviceIDPattern = /^wd_[a-z2-7]{16}$/
const jtiPattern = /^[A-Za-z0-9_-]{22}$/
const encoder = new TextEncoder()

function fail(message) {
  throw new Error(`invalid route authorization: ${message}`)
}

function stringValue(value, name) {
  const text = String(value ?? '').trim()
  if (!text) fail(`${name} is required`)
  return text
}

function deviceID(value, name) {
  const text = stringValue(value, name)
  if (!deviceIDPattern.test(text)) fail(`${name} is invalid`)
  return text
}

function transport(value, name) {
  const text = stringValue(value, name).toLowerCase()
  if (text !== 'lan' && text !== 'internet') {
    fail(`${name} must be lan or internet`)
  }
  return text
}

function safeInteger(value, name, maximum = Number.MAX_SAFE_INTEGER) {
  const number = Number(value)
  if (
    !Number.isSafeInteger(number) ||
    number < 0 ||
    number > maximum
  ) {
    fail(`${name} is invalid`)
  }
  return number
}

function timestampMS(value, name) {
  const parsed = Date.parse(String(value ?? ''))
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    fail(`${name} is invalid`)
  }
  return parsed
}

function encodedString(value) {
  const bytes = encoder.encode(value)
  if (bytes.length > 0xffffffff) fail('string field is too large')

  const framed = new Uint8Array(4 + bytes.length)
  new DataView(framed.buffer).setUint32(0, bytes.length, false)
  framed.set(bytes, 4)
  return framed
}

function encodedUint32(value) {
  const bytes = new Uint8Array(4)
  new DataView(bytes.buffer).setUint32(0, value, false)
  return bytes
}

function encodedUint64(value) {
  const big = BigInt(value)
  if (big < 0n || big > 0xffffffffffffffffn) {
    fail('uint64 field is out of range')
  }

  const bytes = new Uint8Array(8)
  new DataView(bytes.buffer).setBigUint64(0, big, false)
  return bytes
}

function concatenate(parts) {
  let length = 0
  for (const part of parts) length += part.length

  const output = new Uint8Array(length)
  let offset = 0

  for (const part of parts) {
    output.set(part, offset)
    offset += part.length
  }

  return output
}

export function encodeBase64URL(bytes) {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)

  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

export function generateRouteAuthorizationJTI() {
  const raw = new Uint8Array(16)
  crypto.getRandomValues(raw)
  return encodeBase64URL(raw)
}

export function buildRouteAuthorizationClaims(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) {
    fail('grant row is missing')
  }

  const id = stringValue(row.id, 'route id')
  const jti = stringValue(row.jti, 'jti')
  if (!jtiPattern.test(jti)) fail('jti is invalid')

  const source = deviceID(row.source_device_id, 'source device id')
  const router = deviceID(row.router_device_id, 'router device id')
  const destination = deviceID(
    row.destination_device_id,
    'destination device id'
  )

  if (
    source === router ||
    source === destination ||
    router === destination
  ) {
    fail('route devices must be distinct')
  }

  const firstTransport = transport(
    row.first_transport,
    'first transport'
  )
  const secondTransport = transport(
    row.second_transport,
    'second transport'
  )

  const firstCost = safeInteger(
    row.first_cost,
    'first cost',
    MAX_ROUTE_AUTHORIZATION_COST
  )
  const secondCost = safeInteger(
    row.second_cost,
    'second cost',
    MAX_ROUTE_AUTHORIZATION_COST
  )

  if (String(row.permission ?? '') !== ROUTE_AUTHORIZATION_PERMISSION) {
    fail('permission is invalid')
  }

  const issuedAtMS = timestampMS(row.issued_at, 'issued_at')
  const expiresAtMS = timestampMS(row.expires_at, 'expires_at')

  if (
    expiresAtMS <= issuedAtMS ||
    expiresAtMS - issuedAtMS > MAX_ROUTE_AUTHORIZATION_LIFETIME_MS
  ) {
    fail('lifetime is invalid')
  }

  const route = {
    ID: id,
    Source: source,
    Destination: destination,
    Hops: [
      {
        From: source,
        To: router,
        Transport: firstTransport,
        Cost: firstCost,
      },
      {
        From: router,
        To: destination,
        Transport: secondTransport,
        Cost: secondCost,
      },
    ],
    ExpiresAt: new Date(expiresAtMS).toISOString(),
  }

  return {
    route,
    claims: {
      v: ROUTE_AUTHORIZATION_VERSION,
      iss: ROUTE_AUTHORIZATION_ISSUER,
      aud: ROUTE_AUTHORIZATION_AUDIENCE,
      permission: ROUTE_AUTHORIZATION_PERMISSION,
      jti,
      router,
      route,
      iat_unix_ms: issuedAtMS,
      exp_unix_ms: expiresAtMS,
    },
  }
}

export function canonicalRouteAuthorizationMessage(input) {
  if (!input || typeof input !== 'object') {
    fail('authorization is missing')
  }

  const kid = stringValue(input.kid, 'key id')
  if (
    kid.length > 128 ||
    /[\r\n\t]/.test(kid)
  ) {
    fail('key id is invalid')
  }

  const claims = input.claims
  if (!claims || typeof claims !== 'object') {
    fail('claims are missing')
  }

  if (claims.v !== ROUTE_AUTHORIZATION_VERSION) {
    fail('version is invalid')
  }
  if (claims.iss !== ROUTE_AUTHORIZATION_ISSUER) {
    fail('issuer is invalid')
  }
  if (claims.aud !== ROUTE_AUTHORIZATION_AUDIENCE) {
    fail('audience is invalid')
  }
  if (claims.permission !== ROUTE_AUTHORIZATION_PERMISSION) {
    fail('permission is invalid')
  }

  const jti = stringValue(claims.jti, 'jti')
  if (!jtiPattern.test(jti)) fail('jti is invalid')

  const router = deviceID(claims.router, 'router')
  const route = claims.route

  if (!route || typeof route !== 'object') {
    fail('route is missing')
  }

  const routeID = stringValue(route.ID, 'route id')
  const source = deviceID(route.Source, 'route source')
  const destination = deviceID(
    route.Destination,
    'route destination'
  )

  if (!Array.isArray(route.Hops) || route.Hops.length !== 2) {
    fail('route must contain exactly two hops')
  }

  const issuedAtMS = safeInteger(
    claims.iat_unix_ms,
    'issued_at'
  )
  const expiresAtMS = safeInteger(
    claims.exp_unix_ms,
    'expires_at'
  )

  if (
    issuedAtMS <= 0 ||
    expiresAtMS <= issuedAtMS ||
    expiresAtMS - issuedAtMS > MAX_ROUTE_AUTHORIZATION_LIFETIME_MS
  ) {
    fail('lifetime is invalid')
  }

  const routeExpiryMS = Date.parse(String(route.ExpiresAt ?? ''))
  if (
    !Number.isSafeInteger(routeExpiryMS) ||
    routeExpiryMS !== expiresAtMS
  ) {
    fail('route expiry is not canonical')
  }

  const hops = route.Hops.map((hop, index) => ({
    From: deviceID(hop.From, `hop ${index} from`),
    To: deviceID(hop.To, `hop ${index} to`),
    Transport: transport(
      hop.Transport,
      `hop ${index} transport`
    ),
    Cost: safeInteger(
      hop.Cost,
      `hop ${index} cost`,
      MAX_ROUTE_AUTHORIZATION_COST
    ),
  }))

  if (
    hops[0].From !== source ||
    hops[0].To !== router ||
    hops[1].From !== router ||
    hops[1].To !== destination
  ) {
    fail('route/router binding is invalid')
  }

  const parts = [
    encodedString(ROUTE_AUTHORIZATION_DOMAIN),
    encodedUint32(ROUTE_AUTHORIZATION_VERSION),
  ]

  for (const value of [
    kid,
    claims.iss,
    claims.aud,
    claims.permission,
    jti,
    router,
    routeID,
    source,
    destination,
  ]) {
    parts.push(encodedString(value))
  }

  parts.push(
    encodedUint64(issuedAtMS),
    encodedUint64(expiresAtMS),
    encodedUint64(routeExpiryMS),
    encodedUint32(hops.length)
  )

  for (const hop of hops) {
    parts.push(
      encodedString(hop.From),
      encodedString(hop.To),
      encodedString(hop.Transport),
      encodedUint64(hop.Cost)
    )
  }

  return concatenate(parts)
}

export async function signRouteAuthorization(key, kid, row) {
  const built = buildRouteAuthorizationClaims(row)

  const message = canonicalRouteAuthorizationMessage({
    kid,
    claims: built.claims,
  })

  const rawSignature = new Uint8Array(
    await crypto.subtle.sign(
      'Ed25519',
      key,
      message
    )
  )

  if (rawSignature.length !== 64) {
    throw new Error('route authorization signer returned an invalid signature')
  }

  return {
    route: built.route,
    authorization: {
      kid,
      claims: built.claims,
      signature: encodeBase64URL(rawSignature),
    },
  }
}
