import crypto from 'crypto';

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export function generateRSAKeyPair(): KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  return { publicKey, privateKey };
}

export function computeSHA256(data: Buffer | string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function signData(data: string, privateKey: string): string {
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(data);
  return sign.sign({
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
  }, 'base64');
}

export function verifyData(data: string, signature: string, publicKey: string): boolean {
  try {
    const verify = crypto.createVerify('RSA-SHA256');
    verify.update(data);
    return verify.verify({
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    }, signature, 'base64');
  } catch (error) {
    console.error('Verification error:', error);
    return false;
  }
}

export function getFingerprint(publicKey: string): string {
  return computeSHA256(publicKey).substring(0, 16).toUpperCase();
}

export function getPublicKey(privateKey: string): string {
  return crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString();
}
