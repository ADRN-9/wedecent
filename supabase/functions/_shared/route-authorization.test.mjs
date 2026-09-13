import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import test from 'node:test'

import {
  buildRouteAuthorizationClaims,
  canonicalRouteAuthorizationMessage,
  encodeBase64URL,
  signRouteAuthorization,
} from './route-authorization.mjs'

if (!globalThis.crypto) globalThis.crypto = webcrypto

const fixtureRow = {
  id: '00000000-0000-4000-8000-000000000001',
  jti: 'AAECAwQFBgcICQoLDA0ODw',
  source_device_id: 'wd_aaaaaaaaaaaaaaaa',
  router_device_id: 'wd_bbbbbbbbbbbbbbbb',
  destination_device_id: 'wd_cccccccccccccccc',
  first_transport: 'internet',
  second_transport: 'lan',
  first_cost: 10,
  second_cost: 20,
  permission: 'mesh.forward',
  issued_at: '2027-01-15T08:00:00.000Z',
  expires_at: '2027-01-15T08:01:00.000Z',
}

const fixtureKid = 'test-route-key-1'

const canonicalFixture =
  'AAAAGHdlZGVjZW50LW1lc2gtZm9yd2FyZC12MQAAAAEAAAAQdGVzdC1yb3V0ZS1rZXktMQAAABZ3ZWRlY2VudC1jb250cm9sLXBsYW5lAAAAFHdlZGVjZW50LW1lc2gtcm91dGVyAAAADG1lc2guZm9yd2FyZAAAABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3AAAAE3dkX2JiYmJiYmJiYmJiYmJiYmIAAAAkMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAxAAAAE3dkX2FhYWFhYWFhYWFhYWFhYWEAAAATd2RfY2NjY2NjY2NjY2NjY2NjYwAAAaMYXFAAAAABoxhdOmAAAAGjGF06YAAAAAIAAAATd2RfYWFhYWFhYWFhYWFhYWFhYQAAABN3ZF9iYmJiYmJiYmJiYmJiYmJiAAAACGludGVybmV0AAAAAAAAAAoAAAATd2RfYmJiYmJiYmJiYmJiYmJiYgAAABN3ZF9jY2NjY2NjY2NjY2NjY2NjAAAAA2xhbgAAAAAAAAAU'

const expectedSignature =
  'N78uguODnD-5_fs_deqgLrC_9_mY3a4O3dg2hB8mplLvxHI76v-YHBhlzID-QS6vKbOatzTS2K5yNbXcFOo5DQ'

const testPKCS8Base64 =
  'MC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f'

test('canonical route authorization matches Go fixture', () => {
  const built = buildRouteAuthorizationClaims(fixtureRow)
  const message = canonicalRouteAuthorizationMessage({
    kid: fixtureKid,
    claims: built.claims,
  })

  assert.equal(
    encodeBase64URL(message),
    canonicalFixture
  )
})

test('Ed25519 route signature matches Go fixture', async () => {
  const key = await crypto.subtle.importKey(
    'pkcs8',
    Buffer.from(testPKCS8Base64, 'base64'),
    'Ed25519',
    false,
    ['sign']
  )

  const signed = await signRouteAuthorization(
    key,
    fixtureKid,
    fixtureRow
  )

  assert.equal(
    signed.authorization.signature,
    expectedSignature
  )
})

test('canonical message changes when exact route changes', () => {
  const original = buildRouteAuthorizationClaims(fixtureRow)

  const changed = buildRouteAuthorizationClaims({
    ...fixtureRow,
    second_cost: 21,
  })

  const originalMessage = canonicalRouteAuthorizationMessage({
    kid: fixtureKid,
    claims: original.claims,
  })

  const changedMessage = canonicalRouteAuthorizationMessage({
    kid: fixtureKid,
    claims: changed.claims,
  })

  assert.notDeepEqual(
    [...originalMessage],
    [...changedMessage]
  )
})

test('long-lived capabilities are rejected', () => {
  assert.throws(
    () => buildRouteAuthorizationClaims({
      ...fixtureRow,
      expires_at: '2027-01-15T08:02:01.000Z',
    }),
    /lifetime is invalid/
  )
})
