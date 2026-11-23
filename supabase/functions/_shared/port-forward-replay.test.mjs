import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import test from 'node:test'

import {
  canonicalPortForwardAuthorizationMessage,
  decodeBase64URLStrict,
  encodeBase64URL,
  remoteReplayDeviceMessage,
} from './port-forward-replay.mjs'

if (!globalThis.crypto) globalThis.crypto = webcrypto

const fixture = {
  kid: 'ed25519-fixture-key',
  claims: {
    v: 1,
    iss: 'wedecent-control-plane',
    aud: 'wedecent-port-forwarder',
    permission: 'port_forward.local',
    jti: 'MDEyMzQ1Njc4OWFiY2RlZg',
    forwarding_id: '00000000-0000-4000-8000-000000000001',
    direction: 'local',
    initiating_device: 'wd_aaaaaaaaaaaaaaaa',
    destination_device: 'wd_bbbbbbbbbbbbbbbb',
    route: {
      ID: '00000000-0000-4000-8000-000000000002',
      Source: 'wd_aaaaaaaaaaaaaaaa',
      Destination: 'wd_bbbbbbbbbbbbbbbb',
      Hops: [{ From: 'wd_aaaaaaaaaaaaaaaa', To: 'wd_bbbbbbbbbbbbbbbb', Transport: 'internet', Cost: 12 }],
      ExpiresAt: '2027-01-15T08:01:30.000Z',
    },
    destination_address: 'example.com',
    destination_port: 443,
    listener: { address: '127.0.0.1', port: 43123, exposure: 'loopback' },
    protocol: 'tcp',
    iat_unix_ms: Date.parse('2027-01-15T08:00:00.000Z'),
    exp_unix_ms: Date.parse('2027-01-15T08:01:30.000Z'),
    limits: { max_connections: 4, max_duration_seconds: 120, idle_timeout_seconds: 30 },
  },
}

test('strict base64url decoding rejects non-canonical encodings', () => {
  assert.equal(decodeBase64URLStrict(fixture.claims.jti, 16).length, 16)
  assert.throws(() => decodeBase64URLStrict(fixture.claims.jti + '=', 16))
  assert.throws(() => decodeBase64URLStrict('A', 1))
})

test('canonical capability message is deterministic and binds claims', () => {
  const original = canonicalPortForwardAuthorizationMessage(fixture)
  const repeated = canonicalPortForwardAuthorizationMessage(fixture)
  assert.deepEqual([...original], [...repeated])
  assert.equal(encodeBase64URL(original), 'AAAAGHdlZGVjZW50LXBvcnQtZm9yd2FyZC12MQAAAAEAAAATZWQyNTUxOS1maXh0dXJlLWtleQAAABZ3ZWRlY2VudC1jb250cm9sLXBsYW5lAAAAF3dlZGVjZW50LXBvcnQtZm9yd2FyZGVyAAAAEnBvcnRfZm9yd2FyZC5sb2NhbAAAABZNREV5TXpRMU5qYzRPV0ZpWTJSbFpnAAAAJDAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMQAAAAVsb2NhbAAAABN3ZF9hYWFhYWFhYWFhYWFhYWFhAAAAE3dkX2JiYmJiYmJiYmJiYmJiYmIAAAAAAAAAJDAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMgAAABN3ZF9hYWFhYWFhYWFhYWFhYWFhAAAAE3dkX2JiYmJiYmJiYmJiYmJiYmIAAAALZXhhbXBsZS5jb20AAAAJMTI3LjAuMC4xAAAACGxvb3BiYWNrAAAAA3RjcAAAAaMYXFAAAAABoxhdr5AAAAAAAAABuwAAAAAAAKhzAAAAAAAAAAQAAAAAAAAAeAAAAAAAAAAeAAAAAQAAABN3ZF9hYWFhYWFhYWFhYWFhYWFhAAAAE3dkX2JiYmJiYmJiYmJiYmJiYmIAAAAIaW50ZXJuZXQAAAAAAAAADA')
  const digestInput = new Uint8Array(original.length + 64)
  digestInput.set(original)
  digestInput.fill(1, original.length)
  return crypto.subtle.digest('SHA-256', digestInput).then((digest) => {
    assert.equal(
      Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join(''),
      '050c6b5504afa088641d4b7f877450ee8f67c8cd2820fa0fb350713a503877d0',
    )
  }).then(() => {
  const changed = canonicalPortForwardAuthorizationMessage({
    ...fixture,
    claims: { ...fixture.claims, destination_port: 444 },
  })
  assert.notDeepEqual([...original], [...changed])
  })
})

test('canonical capability rejects malformed or overlong claims', () => {
  assert.throws(() => canonicalPortForwardAuthorizationMessage({
    ...fixture,
    claims: { ...fixture.claims, jti: 'bad' },
  }))
  assert.throws(() => canonicalPortForwardAuthorizationMessage({
    ...fixture,
    claims: { ...fixture.claims, exp_unix_ms: fixture.claims.iat_unix_ms + 120001 },
  }))
})

test('device replay proof is domain separated and binds the authorization digest', () => {
  const first = remoteReplayDeviceMessage('wd_aaaaaaaaaaaaaaaa', fixture.claims.jti, fixture.claims.exp_unix_ms, 'a'.repeat(64))
  const changed = remoteReplayDeviceMessage('wd_aaaaaaaaaaaaaaaa', fixture.claims.jti, fixture.claims.exp_unix_ms, 'b'.repeat(64))
  assert.notDeepEqual([...first], [...changed])
  assert.match(encodeBase64URL(new Uint8Array([1, 2, 3])), /^[A-Za-z0-9_-]+$/)
})
