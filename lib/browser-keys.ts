export type BrowserKeyPair = {
  privateKey: CryptoKey;
  publicKeyObject: CryptoKey;
  publicKey: string;
  fingerprint: string;
};

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export async function generateBrowserKeyPair(): Promise<BrowserKeyPair> {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    false,
    ["sign", "verify"],
  );
  const publicKeyDer = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const publicKeyBase64 = toBase64(publicKeyDer);
  const publicKey = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64.match(/.{1,64}/g)?.join("\n")}\n-----END PUBLIC KEY-----\n`;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(publicKey)));
  const fingerprint = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("").slice(0, 16).toUpperCase();

  return { privateKey: pair.privateKey, publicKeyObject: pair.publicKey, publicKey, fingerprint };
}