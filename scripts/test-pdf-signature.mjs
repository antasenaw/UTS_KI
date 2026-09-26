import assert from "node:assert/strict";
import { PDFDocument, StandardFonts } from "pdf-lib";
import { generateBrowserKeyPair } from "../lib/browser-keys.ts";
import { signPdfInBrowser } from "../lib/browser-signature.ts";

const baseUrl = process.env.BASE_URL ?? "http://127.0.0.1:3000";

async function request(path, body) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: body ? "POST" : "GET",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error ?? `${path} returned ${response.status}`);
  return result;
}

const pdf = await PDFDocument.create();
const page = pdf.addPage([612, 792]);
const font = await pdf.embedFont(StandardFonts.Helvetica);
page.drawText("SignVerify automated PDF signature test", { x: 48, y: 720, size: 18, font });
const sourcePdf = new Uint8Array(await pdf.save());
const keys = await generateBrowserKeyPair();
assert.equal(keys.privateKey.extractable, false, "Private key must be non-exportable");
assert.deepEqual(keys.privateKey.usages, ["sign"], "Private key must only have signing usage");
assert.equal((await fetch(`${baseUrl}/api/keys`)).status, 404, "Server key generation endpoint must not exist");
assert.equal((await fetch(`${baseUrl}/api/sign`)).status, 404, "Server signing endpoint must not exist");
const signed = await signPdfInBrowser(sourcePdf, keys, {
  signerName: "Dr. Budi Santoso",
  signerTitle: "Ketua Program Studi",
  institution: "Universitas Teknologi Bandung",
  documentName: "automated-test.pdf",
  additionalSigners: [{ name: "Nina Rahmawati", title: "Koordinator Administrasi" }],
  verifyBaseUrl: baseUrl,
});
const signedPdf = Buffer.from(signed.signedPdf);
const signedPdfBase64 = signedPdf.toString("base64");
const valid = await request("/api/verify", { data: signedPdfBase64 });
assert.equal(valid.valid, true, `A: original signed PDF and embedded QR must verify: ${JSON.stringify(valid)}`);
assert.equal(valid.pdfSignatureValid, true, "G: CMS PDF signature must parse and verify");
assert.equal(valid.visualQrScanned, true, "H: QR must decode from rendered PDF pixels");
assert.ok(valid.qrPayload, "Verifier must return the scanned QR payload");

const byteTamper = Buffer.from(signedPdf);
byteTamper[10] ^= 1;
const byteTamperResult = await request("/api/verify", { data: byteTamper.toString("base64") });
assert.equal(byteTamperResult.valid, false, "B: a one-byte PDF change must fail");

const catalogMarker = Buffer.from("/Type /Catalog");
const catalogOffset = signedPdf.indexOf(catalogMarker);
assert.ok(catalogOffset >= 0, "Test PDF catalog marker must be present");
const characterTamper = Buffer.from(signedPdf);
characterTamper[catalogOffset + 7] = "B".charCodeAt(0);
const characterTamperResult = await request("/api/verify", { data: characterTamper.toString("base64") });
assert.equal(characterTamperResult.valid, false, "C: a one-character PDF change must fail");

const wrongKeys = await generateBrowserKeyPair();
const wrongKeyResult = await request("/api/verify", { data: signedPdfBase64, publicKey: wrongKeys.publicKey });
assert.equal(wrongKeyResult.valid, false, "D: a wrong public key must fail");
assert.equal(wrongKeyResult.expectedKeyMatches, false);

const fakeQr = { ...valid.qrPayload, signerName: "Forged Signer" };
const fakeQrResult = await request("/api/verify", { data: signedPdfBase64, qrPayload: fakeQr });
assert.equal(fakeQrResult.valid, false, "E: a fake QR payload with original PDF must fail");
assert.equal(fakeQrResult.qrMatchesPdf, false);

const changedQr = { ...valid.qrPayload, documentId: "forged-document-id" };
const changedQrResult = await request("/api/verify", { data: signedPdfBase64, qrPayload: changedQr });
assert.equal(changedQrResult.valid, false, "F: altered QR data must be detected");
assert.equal(changedQrResult.qrMatchesPdf, false);

assert.ok(signed.signedSize > signed.sourceSize, "Signed PDF must include the QR appearance and signature container");
console.log(JSON.stringify({
  passed: true,
  tests: {
    signedPdfWithEmbeddedQr: valid.valid,
    oneByteTamperRejected: !byteTamperResult.valid,
    oneCharacterTamperRejected: !characterTamperResult.valid,
    wrongPublicKeyRejected: !wrongKeyResult.valid,
    fakeQrRejected: !fakeQrResult.valid,
    changedQrRejected: !changedQrResult.valid,
    pdfParsedAndRendered: valid.pdfSignatureValid && valid.visualQrScanned,
    qrDecodedFromPdfPixels: valid.visualQrScanned,
  },
  measurements: {
    sourcePdfBytes: signed.sourceSize,
    signedPdfBytes: signed.signedSize,
    cmsSignatureBytes: signed.signatureBytes,
    publicKeyPemBytes: signed.publicKeyBytes,
  },
}, null, 2));