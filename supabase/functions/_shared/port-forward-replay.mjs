import { canonicalRouteAuthorizationMessage } from './route-authorization.mjs'

const encoder = new TextEncoder()
const deviceIDPattern = /^wd_[a-z2-7]{16}$/
const jtiPattern = /^[A-Za-z0-9_-]{22}$/
const forwardingIDPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const domain = 'wedecent-port-forward-v1'

function fail(message) {
  throw new Error(`invalid port-forward replay authorization: ${message}`)
}

function stringField(value, name, allowEmpty = false) {
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0) || /[\r\n\t]/.test(value)) {
    fail(`${name} is invalid`)
  }
  return value
}

function safeInteger(value, name, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${name} is invalid`)
  }
  return value
}

function deviceID(value, name) {
  const result = stringField(value, name)
  if (!deviceIDPattern.test(result)) fail(`${name} is invalid`)
  return result
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
  const integer = BigInt(value)
  if (integer < 0n || integer > 0xffffffffffffffffn) fail('uint64 field is out of range')
  const bytes = new Uint8Array(8)
  new DataView(bytes.buffer).setBigUint64(0, integer, false)
  return bytes
}

function concatenate(parts) {
  const length = parts.reduce((total, part) => total + part.length, 0)
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
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

export function decodeBase64URLStrict(value, expectedLength) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    fail('base64url value is not canonical')
  }
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)
  let binary
  try {
    binary = atob(padded)
  } catch {
    fail('base64url value cannot be decoded')
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
  if (encodeBase64URL(bytes) !== value || (expectedLength !== undefined && bytes.length !== expectedLength)) {
    fail('base64url value has an invalid length or encoding')
  }
  return bytes
}

export function canonicalPortForwardAuthorizationMessage(authorization) {
  if (!authorization || typeof authorization !== 'object' || Array.isArray(authorization)) fail('authorization is missing')
  const kid = stringField(authorization.kid, 'key id')
  if (kid.length > 128) fail('key id is too long')
  const claims = authorization.claims
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) fail('claims are missing')

  if (claims.v !== 1 || claims.iss !== 'wedecent-control-plane' || claims.aud !== 'wedecent-port-forwarder' || claims.protocol !== 'tcp') {
    fail('issuer, audience, version, or protocol is invalid')
  }
  const direction = stringField(claims.direction, 'direction')
  if (direction !== 'local' && direction !== 'remote') fail('direction is invalid')
  const permission = direction === 'local' ? 'port_forward.local' : 'port_forward.remote'
  if (claims.permission !== permission) fail('permission is invalid')
  const jti = stringField(claims.jti, 'jti')
  if (!jtiPattern.test(jti)) fail('jti is invalid')
  decodeBase64URLStrict(jti, 16)
  const forwardingID = stringField(claims.forwarding_id, 'forwarding id')
  if (!forwardingIDPattern.test(forwardingID)) fail('forwarding id is invalid')
  const initiating = deviceID(claims.initiating_device, 'initiating device')
  const destination = deviceID(claims.destination_device, 'destination device')
  if (initiating === destination) fail('endpoint devices must differ')
  const router = claims.router === undefined ? '' : stringField(claims.router, 'router', true)
  if (router && (!deviceIDPattern.test(router) || router === initiating || router === destination)) fail('router is invalid')

  const issued = safeInteger(claims.iat_unix_ms, 'issued time', 1)
  const expires = safeInteger(claims.exp_unix_ms, 'expiry', 1)
  if (expires <= issued || expires - issued > 120000) fail('authorization lifetime is invalid')

  const route = claims.route
  if (!route || typeof route !== 'object' || Array.isArray(route)) fail('route is missing')
  const routeID = stringField(route.ID, 'route id')
  const routeSource = deviceID(route.Source, 'route source')
  const routeDestination = deviceID(route.Destination, 'route destination')
  const expectedSource = direction === 'local' ? initiating : destination
  const expectedDestination = direction === 'local' ? destination : initiating
  if (routeSource !== expectedSource || routeDestination !== expectedDestination) fail('route endpoint binding is invalid')
  if (Date.parse(stringField(route.ExpiresAt, 'route expiry')) !== expires) fail('route expiry is not canonical')
  if (!Array.isArray(route.Hops) || route.Hops.length < 1 || route.Hops.length > 2) fail('route hop count is invalid')

  let expectedFrom = routeSource
  const visited = new Set([routeSource])
  const hops = route.Hops.map((hop, index) => {
    if (!hop || typeof hop !== 'object' || Array.isArray(hop)) fail(`route hop ${index} is invalid`)
    const from = deviceID(hop.From, `route hop ${index} source`)
    const to = deviceID(hop.To, `route hop ${index} destination`)
    const transport = stringField(hop.Transport, `route hop ${index} transport`)
    const cost = safeInteger(hop.Cost, `route hop ${index} cost`)
    if (from !== expectedFrom || from === to || visited.has(to)) fail('route is discontinuous or cyclic')
    visited.add(to)
    expectedFrom = to
    return { from, to, transport, cost }
  })
  if (expectedFrom !== routeDestination) fail('route does not terminate at destination')
  if (hops.length === 1 && router !== '') fail('direct route must not name a router')
  if (hops.length === 2 && (!router || hops[0].to !== router || hops[1].from !== router)) fail('routed path does not bind its router')

  const destinationAddress = stringField(claims.destination_address, 'destination address')
  if (destinationAddress !== destinationAddress.toLowerCase() || /[\s%/\\@]/.test(destinationAddress)) fail('destination address is not canonical')
  const destinationPort = safeInteger(claims.destination_port, 'destination port', 1, 65535)
  const listener = claims.listener
  if (!listener || typeof listener !== 'object' || Array.isArray(listener)) fail('listener is missing')
  const listenerAddress = stringField(listener.address, 'listener address')
  if (/[\s%/\\@]/.test(listenerAddress)) fail('listener address is invalid')
  const listenerPort = safeInteger(listener.port, 'listener port', 1, 65535)
  const exposure = stringField(listener.exposure, 'listener exposure')
  if (!['loopback', 'private', 'public'].includes(exposure)) fail('listener exposure is invalid')
  const limits = claims.limits
  if (!limits || typeof limits !== 'object' || Array.isArray(limits)) fail('resource limits are missing')
  const maxConnections = safeInteger(limits.max_connections, 'maximum connections', 1, 64)
  const maxDuration = safeInteger(limits.max_duration_seconds, 'maximum duration', 1, 3600)
  const idleTimeout = safeInteger(limits.idle_timeout_seconds, 'idle timeout', 5, 900)

  const parts = [encodedString(domain), encodedUint32(1)]
  for (const value of [
    kid, claims.iss, claims.aud, permission, jti, forwardingID,
    direction, initiating, destination, router, routeID, routeSource,
    routeDestination, destinationAddress, listenerAddress, exposure, 'tcp',
  ]) {
    parts.push(encodedString(value))
  }
  for (const value of [
    issued, expires, destinationPort, listenerPort,
    maxConnections, maxDuration, idleTimeout,
  ]) {
    parts.push(encodedUint64(value))
  }
  parts.push(encodedUint32(hops.length))
  for (const hop of hops) {
    parts.push(encodedString(hop.from), encodedString(hop.to), encodedString(hop.transport), encodedUint64(hop.cost))
  }
  return concatenate(parts)
}

function asArrayBuffer(bytes) {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer
}

export async function deviceIDFromPublicKey(publicKeyBytes) {
  if (!(publicKeyBytes instanceof Uint8Array) || publicKeyBytes.length !== 32) {
    fail('device public key has an invalid length')
  }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', asArrayBuffer(publicKeyBytes)))
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567'
  let accumulator = 0
  let bits = 0
  let encoded = ''
  for (const byte of digest.subarray(0, 10)) {
    accumulator = (accumulator << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      encoded += alphabet[(accumulator >> bits) & 31]
      accumulator &= (1 << bits) - 1
    }
  }
  if (bits !== 0 || encoded.length !== 16) fail('device identity derivation failed')
  return 'wd_' + encoded
}

export function remoteReplayDeviceMessage(deviceID, jti, expiresAtUnixMS, authorizationSHA256) {
  if (!deviceIDPattern.test(deviceID) || !jtiPattern.test(jti) || !/^[0-9a-f]{64}$/.test(authorizationSHA256)) {
    fail('device replay proof fields are invalid')
  }
  safeInteger(expiresAtUnixMS, 'expiry', 1)
  return encoder.encode(
    'wedecent-port-forward-replay-consume-v1\n' +
    `device_id=${deviceID}\n` +
    `jti=${jti}\n` +
    `expires_at_unix_ms=${expiresAtUnixMS}\n` +
    `authorization_sha256=${authorizationSHA256}\n`,
  )
}


export async function verifyRouteAuthorizationBinding(
  authorization,
  capabilityClaims,
  publicKeyBytes,
) {
  const nested = authorization?.route_authorization
  const router = capabilityClaims?.router ?? ''
  if (!router) {
    if (nested != null && (nested.kid || nested.signature || nested.claims?.jti)) {
      fail('direct route must not include router authorization')
    }
    return null
  }
  if (
    !(publicKeyBytes instanceof Uint8Array) ||
    publicKeyBytes.length !== 32 ||
    !nested ||
    typeof nested !== 'object' ||
    Array.isArray(nested)
  ) fail('router authorization is missing')

  const routeClaims = nested.claims
  if (!routeClaims || typeof routeClaims !== 'object' || Array.isArray(routeClaims)) {
    fail('router authorization claims are missing')
  }
  const keyDigest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', publicKeyBytes),
  )
  const expectedKid = 'ed25519-' + encodeBase64URL(keyDigest)
  if (nested.kid !== expectedKid) fail('router authorization key identifier mismatch')

  const message = canonicalRouteAuthorizationMessage(nested)
  const signature = decodeBase64URLStrict(nested.signature, 64)
  const key = await crypto.subtle.importKey(
    'raw',
    asArrayBuffer(publicKeyBytes),
    { name: 'Ed25519' },
    false,
    ['verify'],
  )
  if (!await crypto.subtle.verify(
    { name: 'Ed25519' },
    key,
    asArrayBuffer(signature),
    asArrayBuffer(message),
  )) fail('router authorization signature rejected')

  const route = routeClaims.route
  const capabilityRoute = capabilityClaims.route
  if (
    routeClaims.router !== router ||
    routeClaims.jti == null ||
    !/^[A-Za-z0-9_-]{22}$/.test(routeClaims.jti) ||
    routeClaims.iat_unix_ms > capabilityClaims.iat_unix_ms ||
    routeClaims.exp_unix_ms !== capabilityClaims.exp_unix_ms ||
    route?.ID !== capabilityRoute?.ID ||
    route?.Source !== capabilityRoute?.Source ||
    route?.Destination !== capabilityRoute?.Destination ||
    route?.ExpiresAt !== capabilityRoute?.ExpiresAt ||
    !Array.isArray(route?.Hops) ||
    !Array.isArray(capabilityRoute?.Hops) ||
    route.Hops.length !== 2 ||
    capabilityRoute.Hops.length !== 2 ||
    route.Hops.some((hop, index) => {
      const expected = capabilityRoute.Hops[index]
      return !expected ||
        hop.From !== expected.From ||
        hop.To !== expected.To ||
        hop.Transport !== expected.Transport ||
        hop.Cost !== expected.Cost
    })
  ) fail('router authorization does not bind the exact signed route')

  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(route.ID)) {
    fail('router authorization route id is invalid')
  }
  return {
    id: route.ID,
    jti: routeClaims.jti,
    sourceDeviceID: route.Source,
    destinationDeviceID: route.Destination,
    firstTransport: route.Hops[0].Transport,
    secondTransport: route.Hops[1].Transport,
    firstCost: route.Hops[0].Cost,
    secondCost: route.Hops[1].Cost,
  }
}
