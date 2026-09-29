import { computeSHA256, getFingerprint, verifyData } from "@/lib/crypto";
import { getSignedQrPayload, scanPdfQrPayload, verifyPdfByteRange } from "@/lib/pdf-signature";

export const runtime = "nodejs";
const MAX_PDF_BYTES = 25 * 1024 * 1024;

type QrPayload = {
  app: string;
  documentId: string;
  documentName: string;
  signerName: string;
  signerTitle: string;
  institution: string;
  additionalSigners: { name: string; title: string }[];
  signedAt: string;
  sourceHash: string;
  fingerprint: string;
  algorithm: string;
  verifyUrl: string;
  metadataSignature: string;
};

function qrSigningData(payload: QrPayload): string {
  return JSON.stringify({
    app: payload.app,
    documentId: payload.documentId,
    documentName: payload.documentName,
    signerName: payload.signerName,
    signerTitle: payload.signerTitle,
    institution: payload.institution,
    additionalSigners: payload.additionalSigners,
    signedAt: payload.signedAt,
    sourceHash: payload.sourceHash,
    fingerprint: payload.fingerprint,
    algorithm: payload.algorithm,
    verifyUrl: payload.verifyUrl,
  });
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

async function verifySignedPdf(pdf: Buffer, externalPayload: unknown, expectedPublicKey?: string) {
  const signature = await verifyPdfByteRange(pdf);
  const embeddedPayloadJson = getSignedQrPayload(pdf);
  const embeddedPayload = JSON.parse(embeddedPayloadJson) as QrPayload;
  let scannedPayload: QrPayload | null = null;
  let qrScanError = "";
  try { scannedPayload = JSON.parse(await scanPdfQrPayload(pdf)) as QrPayload; }
  catch (error) { qrScanError = error instanceof Error ? error.message : "QR scan failed."; }
  const suppliedPayload = externalPayload && typeof externalPayload === "object" ? externalPayload : scannedPayload ?? embeddedPayload;
  const qrMatchesPdf = stableJson(suppliedPayload) === stableJson(embeddedPayload);
  const visualQrScanned = Boolean(scannedPayload && stableJson(scannedPayload) === stableJson(embeddedPayload));
  const metadataValid = embeddedPayload.app === "Verisign"
    && embeddedPayload.algorithm === "RSA-PSS-2048-SHA256"
    && embeddedPayload.fingerprint === getFingerprint(signature.publicKeyPem)
    && verifyData(qrSigningData(embeddedPayload), embeddedPayload.metadataSignature, signature.publicKeyPem);
  const expectedKeyMatches = !expectedPublicKey || getFingerprint(expectedPublicKey) === embeddedPayload.fingerprint;
  const valid = signature.valid && qrMatchesPdf && visualQrScanned && metadataValid && expectedKeyMatches;

  return {
    valid,
    pdfSignatureValid: signature.valid,
    qrMatchesPdf,
    visualQrScanned,
    qrScanError,
    metadataValid,
    expectedKeyMatches,
    hash: computeSHA256(pdf),
    sourceHash: embeddedPayload.sourceHash,
    fingerprint: embeddedPayload.fingerprint,
    documentId: embeddedPayload.documentId,
    signatureBytes: signature.signatureBytes,
    qrPayload: embeddedPayload,
  };
}

export async function POST(request: Request) {
  try {
    const { data, publicKey, signature, qrPayload } = await request.json() as { data?: string; publicKey?: string; signature?: string; qrPayload?: unknown };
    if (typeof data !== "string" || !data) return Response.json({ error: "PDF data is required." }, { status: 400 });
    if (data.length > Math.ceil(MAX_PDF_BYTES / 3) * 4) return Response.json({ error: "PDF exceeds the 25 MB verification limit." }, { status: 413 });
    const pdf = Buffer.from(data, "base64");
    if (pdf.byteLength > MAX_PDF_BYTES) return Response.json({ error: "PDF exceeds the 25 MB verification limit." }, { status: 413 });
    if (pdf.subarray(0, 5).toString("ascii") !== "%PDF-") return Response.json({ error: "Only PDF files can be verified." }, { status: 400 });
    if (qrPayload || !publicKey || !signature) return Response.json(await verifySignedPdf(pdf, qrPayload, publicKey));
    const hash = computeSHA256(pdf);
    return Response.json({ valid: verifyData(hash, signature, publicKey), hash, fingerprint: getFingerprint(publicKey) });
  } catch (error) {
    return Response.json({ valid: false, pdfSignatureValid: false, qrMatchesPdf: false, metadataValid: false, expectedKeyMatches: false, hash: "", fingerprint: "", error: error instanceof Error ? error.message : "Verification failed." });
  }
}