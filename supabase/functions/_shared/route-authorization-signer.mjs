const encoder = new TextEncoder()

export function encodeBase64URL(bytes) {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function decodePKCS8Base64(value) {
  const text = String(value ?? '').trim()
  if (!text || text.length > 8192 || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) {
    throw new Error('route authorization PKCS8 key is invalid')
  }
  const binary = atob(text)
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0))
  if (bytes.length < 48 || bytes.length > 4096 || btoa(binary) !== text) {
    throw new Error('route authorization PKCS8 key is invalid')
  }
  return bytes
}

function decodePublicKeyBase64URL(value) {
  const text = String(value ?? '').trim()
  if (!/^[A-Za-z0-9_-]{43}$/.test(text)) {
    throw new Error('route authorization public key is invalid')
  }
  const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '='
  const bytes = Uint8Array.from(atob(padded), (char) => char.charCodeAt(0))
  if (bytes.length !== 32 || encodeBase64URL(bytes) !== text) {
    throw new Error('route authorization public key is invalid')
  }
  return bytes
}

export async function loadRouteAuthorizationSigner(privatePKCS8Base64, publicKeyBase64URL) {
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    decodePKCS8Base64(privatePKCS8Base64),
    { name: 'Ed25519' },
    false,
    ['sign'],
  )
  const publicBytes = decodePublicKeyBase64URL(publicKeyBase64URL)
  const publicKey = await crypto.subtle.importKey(
    'raw',
    publicBytes,
    { name: 'Ed25519' },
    true,
    ['verify'],
  )
  const jwkThumbprintInput = JSON.stringify({
    crv: 'Ed25519',
    kty: 'OKP',
    x: encodeBase64URL(publicBytes),
  })
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(jwkThumbprintInput)))
  const kid = encodeBase64URL(digest)
  const challenge = encoder.encode('wedecent-route-authorization-key-check-v1')
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, challenge)
  if (privateKey.extractable || !await crypto.subtle.verify({ name: 'Ed25519' }, publicKey, signature, challenge)) {
    throw new Error('route authorization private/public key mismatch')
  }
  return { key: privateKey, kid }
}
