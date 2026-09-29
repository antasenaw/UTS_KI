import { createPublicKey, webcrypto } from "node:crypto";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import jsQR from "jsqr";
import { inflateSync } from "node:zlib";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const RSA_PSS_OID = "1.2.840.113549.1.1.10";
const cryptoEngine = new pkijs.CryptoEngine({ name: "Verisign-node", crypto: webcrypto as unknown as Crypto });
pkijs.setEngine("Verisign-node", cryptoEngine);

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
}

export async function verifyPdfByteRange(pdfBuffer: Buffer): Promise<{ valid: boolean; publicKeyPem: string; signatureBytes: number }> {
  const pdfText = pdfBuffer.toString("latin1");
  const match = /\/ByteRange\s*\[\s*0\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/.exec(pdfText);
  if (!match) throw new Error("PDF signature ByteRange was not found.");

  const firstLength = Number(match[1]);
  const secondStart = Number(match[2]);
  const secondLength = Number(match[3]);
  if (!Number.isSafeInteger(firstLength) || !Number.isSafeInteger(secondStart) || !Number.isSafeInteger(secondLength) || secondStart + secondLength !== pdfBuffer.length || firstLength <= 0 || firstLength >= secondStart) {
    throw new Error("PDF signature ByteRange is invalid.");
  }

  const contentsGap = pdfBuffer.subarray(firstLength, secondStart);
  const openBracket = contentsGap.indexOf(0x3c);
  const closeBracket = contentsGap.indexOf(0x3e, openBracket + 1);
  if (openBracket < 0 || closeBracket < 0) throw new Error("PDF signature contents were not found.");
  const signatureHex = contentsGap.subarray(openBracket + 1, closeBracket).toString("ascii").replace(/\s/g, "");
  const paddedCms = Buffer.from(signatureHex, "hex");
  const parsedCms = asn1js.fromBER(toArrayBuffer(paddedCms));
  if (parsedCms.offset <= 0) throw new Error("PDF CMS signature is malformed.");

  const contentInfo = new pkijs.ContentInfo({ schema: parsedCms.result });
  if (contentInfo.contentType !== pkijs.ContentInfo.SIGNED_DATA) throw new Error("PDF signature is not CMS SignedData.");
  const signedData = new pkijs.SignedData({ schema: contentInfo.content });
  const signerInfo = signedData.signerInfos[0];
  if (!signerInfo || signerInfo.signatureAlgorithm.algorithmId !== RSA_PSS_OID || signerInfo.digestAlgorithm.algorithmId !== SHA256_OID) {
    throw new Error("PDF signature algorithm is not RSA-PSS with SHA-256.");
  }
  const certificate = signedData.certificates?.find((item): item is pkijs.Certificate => item instanceof pkijs.Certificate);
  if (!certificate) throw new Error("PDF signature does not contain a signer certificate.");

  const byteRangeContent = Buffer.concat([pdfBuffer.subarray(0, firstLength), pdfBuffer.subarray(secondStart, secondStart + secondLength)]);
  const valid = await signedData.verify({ signer: 0, data: toArrayBuffer(byteRangeContent), checkChain: false }, cryptoEngine);
  const certificatePublicKey = await certificate.getPublicKey();
  const publicKeyPem = createPublicKey({ key: Buffer.from(await webcrypto.subtle.exportKey("spki", certificatePublicKey)), format: "der", type: "spki" })
    .export({ type: "spki", format: "pem" }).toString();
  return { valid, publicKeyPem, signatureBytes: Buffer.from(paddedCms.subarray(0, parsedCms.offset)).byteLength };
}

export function getSignedQrPayload(pdfBuffer: Buffer): string {
  const pdfText = pdfBuffer.toString("latin1");
  const match = /\/Reason\s*\(Verisign1:([A-Za-z0-9_-]+)\)/.exec(pdfText);
  if (!match) throw new Error("Signed QR payload was not found in the PDF signature dictionary.");
  return Buffer.from(match[1], "base64url").toString("utf8");
}

export async function scanPdfQrPayload(pdfBuffer: Buffer): Promise<string> {
  const loadNativeCanvas = createRequire(`${process.cwd()}/package.json`);
  const { createCanvas } = loadNativeCanvas("@napi-rs/canvas") as typeof import("@napi-rs/canvas");
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  pdfjs.GlobalWorkerOptions.workerSrc = pathToFileURL(loadNativeCanvas.resolve("pdfjs-dist/legacy/build/pdf.worker.mjs")).href;
  const loadingTask = pdfjs.getDocument({ data: new Uint8Array(pdfBuffer), useSystemFonts: true });
  const pdf = await loadingTask.promise;
  try {
    const page = await pdf.getPage(pdf.numPages);
    const naturalSize = page.getViewport({ scale: 1 });
    const scale = Math.min(4, 2400 / Math.max(naturalSize.width, naturalSize.height));
    const viewport = page.getViewport({ scale });
    const canvas = createCanvas(Math.ceil(viewport.width), Math.ceil(viewport.height));
    const context = canvas.getContext("2d");
    await page.render({ canvas: canvas as unknown as HTMLCanvasElement, viewport, annotationMode: 0 }).promise;
    const image = context.getImageData(0, 0, canvas.width, canvas.height);
    const result = jsQR(image.data, image.width, image.height, { inversionAttempts: "attemptBoth" });
    if (!result || !result.data.startsWith("SV1:")) throw new Error("No scannable Verisign QR was found on the final PDF page.");
    return inflateSync(Buffer.from(result.data.slice(4), "base64url")).toString("utf8");
  } finally {
    void loadingTask.destroy();
  }
}