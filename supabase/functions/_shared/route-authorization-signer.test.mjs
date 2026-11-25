import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import test from 'node:test'
import { encodeBase64URL, loadRouteAuthorizationSigner } from './route-authorization-signer.mjs'

if (!globalThis.crypto) globalThis.crypto = webcrypto

function encodeBase64(bytes) {
  return Buffer.from(bytes).toString('base64')
}

async function keyMaterial() {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  return {
    privateKey: encodeBase64(await crypto.subtle.exportKey('pkcs8', pair.privateKey)),
    publicKey: encodeBase64URL(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))),
  }
}

test('imports a non-extractable signer and derives kid from separate public key', async () => {
  const material = await keyMaterial()
  const signer = await loadRouteAuthorizationSigner(material.privateKey, material.publicKey)
  assert.equal(signer.key.extractable, false)
  assert.match(signer.kid, /^[A-Za-z0-9_-]{43}$/)
})

test('rejects mismatched private and separately provisioned public keys', async () => {
  const privateMaterial = await keyMaterial()
  const otherMaterial = await keyMaterial()
  await assert.rejects(
    loadRouteAuthorizationSigner(privateMaterial.privateKey, otherMaterial.publicKey),
    /private\/public key mismatch/,
  )
})

test('rejects malformed or non-canonical public key material', async () => {
  const material = await keyMaterial()
  await assert.rejects(loadRouteAuthorizationSigner(material.privateKey, 'not-a-key'), /public key is invalid/)
})
