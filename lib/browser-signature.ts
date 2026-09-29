import { deflate } from "pako";
import QRCode from "qrcode";
import { PDFDocument, StandardFonts, rgb } from "pdf-lib";
import { pdflibAddPlaceholder } from "@signpdf/placeholder-pdf-lib";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import type { BrowserKeyPair } from "@/lib/browser-keys";

const encoder = new TextEncoder();
const RSA_PSS_OID = "1.2.840.113549.1.1.10";

export type BrowserQrPayload = {
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

export type BrowserSigningResult = {
  signedPdf: Uint8Array;
  sourceHash: string;
  signature: string;
  publicKey: string;
  fingerprint: string;
  qrCode: string;
  qrPayload: BrowserQrPayload;
  signedAt: string;
  documentId: string;
  algorithm: string;
  sourceSize: number;
  signedSize: number;
  signatureBytes: number;
  publicKeyBytes: number;
};

type SignerInput = {
  signerName: string;
  signerTitle: string;
  institution: string;
  documentName: string;
  additionalSigners: { name: string; title: string }[];
  verifyBaseUrl?: string;
};

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function safePdfText(value: string): string {
  return value.normalize("NFKD").replace(/[^\x20-\x7E]/g, "?");
}

function findAscii(bytes: Uint8Array, value: string, start = 0): number {
  const search = encoder.encode(value);
  outer: for (let index = start; index <= bytes.length - search.length; index += 1) {
    for (let offset = 0; offset < search.length; offset += 1) {
      if (bytes[index + offset] !== search[offset]) continue outer;
    }
    return index;
  }
  return -1;
}

function concatBytes(first: Uint8Array, second: Uint8Array): Uint8Array {
  const output = new Uint8Array(first.length + second.length);
  output.set(first);
  output.set(second, first.length);
  return output;
}

async function signMetadata(payload: Omit<BrowserQrPayload, "metadataSignature">, privateKey: CryptoKey): Promise<string> {
  const signature = await crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    privateKey,
    encoder.encode(JSON.stringify(payload)),
  );
  return toBase64(new Uint8Array(signature));
}

async function createSessionCertificate(publicKey: CryptoKey, privateKey: CryptoKey, engine: pkijs.CryptoEngine): Promise<pkijs.Certificate> {
  const certificate = new pkijs.Certificate();
  certificate.version = 2;
  certificate.serialNumber = new asn1js.Integer({ value: Date.now() });
  const commonName = new pkijs.AttributeTypeAndValue({
    type: "2.5.4.3",
    value: new asn1js.Utf8String({ value: "Verisign Session" }),
  });
  certificate.issuer.typesAndValues.push(commonName);
  certificate.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({ type: commonName.type, value: commonName.value }));
  certificate.notBefore.value = new Date(Date.now() - 60_000);
  certificate.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
  await certificate.subjectPublicKeyInfo.importKey(publicKey);
  await certificate.sign(privateKey, "SHA-256", engine);
  return certificate;
}

async function createCmsSignature(data: Uint8Array, privateKey: CryptoKey, certificate: pkijs.Certificate, engine: pkijs.CryptoEngine): Promise<Uint8Array> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(data)));
  const certificateDer = new Uint8Array(certificate.toSchema(true).toBER(false));
  const certificateDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(certificateDer)));
  const utcTime = new Date().toISOString().replace(/[-:T]/g, "").replace(/\.\d{3}Z$/, "Z").slice(2);
  const signedAttributes = new pkijs.SignedAndUnsignedAttributes({
    type: 0,
    attributes: [
      new pkijs.Attribute({ type: "1.2.840.113549.1.9.3", values: [new asn1js.ObjectIdentifier({ value: pkijs.ContentInfo.DATA })] }),
      new pkijs.Attribute({ type: "1.2.840.113549.1.9.4", values: [new asn1js.OctetString({ valueHex: toArrayBuffer(digest) })] }),
      new pkijs.Attribute({ type: "1.2.840.113549.1.9.5", values: [new asn1js.UTCTime({ value: utcTime })] }),
      new pkijs.Attribute({
        type: "1.2.840.113549.1.9.16.2.47",
        values: [new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [new asn1js.OctetString({ valueHex: toArrayBuffer(certificateDigest) })] })] })] })],
      }),
    ],
  });
  const signerInfo = new pkijs.SignerInfo({
    sid: new pkijs.IssuerAndSerialNumber({ issuer: certificate.issuer, serialNumber: certificate.serialNumber }),
    signedAttrs: signedAttributes,
  });
  const signedData = new pkijs.SignedData({
    encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: pkijs.ContentInfo.DATA }),
    signerInfos: [signerInfo],
    certificates: [certificate],
  });

  await signedData.sign(privateKey, 0, "SHA-256", toArrayBuffer(data), engine);
  if (signerInfo.signatureAlgorithm.algorithmId !== RSA_PSS_OID) throw new Error("CMS signer did not select RSASSA-PSS.");
  const contentInfo = new pkijs.ContentInfo({ contentType: pkijs.ContentInfo.SIGNED_DATA, content: signedData.toSchema(true) });
  return new Uint8Array(contentInfo.toSchema().toBER(false));
}

async function finalizePdf(preparedPdf: Uint8Array, createSignature: (bytes: Uint8Array) => Promise<Uint8Array>): Promise<{ pdf: Uint8Array; cmsBytes: number }> {
  let pdf = preparedPdf;
  if (pdf[pdf.length - 1] === 0x0a) pdf = pdf.subarray(0, pdf.length - 1);
  if (pdf[pdf.length - 1] === 0x0d) pdf = pdf.subarray(0, pdf.length - 1);
  const byteRangeStart = findAscii(pdf, "/ByteRange");
  const byteRangeOpen = findAscii(pdf, "[", byteRangeStart);
  const byteRangeClose = findAscii(pdf, "]", byteRangeOpen);
  const contentsTag = findAscii(pdf, "/Contents ", byteRangeClose);
  const contentsOpen = findAscii(pdf, "<", contentsTag);
  const contentsClose = findAscii(pdf, ">", contentsOpen);
  if (byteRangeStart < 0 || byteRangeOpen < 0 || byteRangeClose < 0 || contentsTag < 0 || contentsOpen < 0 || contentsClose < 0) {
    throw new Error("PDF signature placeholder could not be found.");
  }

  const firstLength = contentsOpen;
  const secondStart = contentsClose + 1;
  const secondLength = pdf.length - secondStart;
  const placeholderLength = byteRangeClose + 1 - byteRangeStart;
  const actualByteRange = `/ByteRange [0 ${firstLength} ${secondStart} ${secondLength}]`;
  if (actualByteRange.length > placeholderLength) throw new Error("PDF is too large for the signature ByteRange placeholder.");
  pdf.set(encoder.encode(actualByteRange.padEnd(placeholderLength, " ")), byteRangeStart);

  const signedBytes = concatBytes(pdf.subarray(0, firstLength), pdf.subarray(secondStart));
  const cms = await createSignature(signedBytes);
  const contentsHexLength = contentsClose - contentsOpen - 1;
  if (cms.length * 2 > contentsHexLength) throw new Error("CMS signature exceeds the PDF placeholder length.");
  pdf.set(encoder.encode(hex(cms).padEnd(contentsHexLength, "0")), contentsOpen + 1);
  return { pdf, cmsBytes: cms.byteLength };
}

export async function signPdfInBrowser(sourcePdf: Uint8Array, keys: BrowserKeyPair, input: SignerInput): Promise<BrowserSigningResult> {
  const cryptoEngine = new pkijs.CryptoEngine({ name: "VerisignBrowser", crypto: crypto as Crypto });
  const sourceHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(sourcePdf))));
  const documentId = crypto.randomUUID();
  const signedAt = new Date().toISOString();
  const metadata = {
    app: "Verisign",
    documentId,
    documentName: input.documentName.trim() || "document.pdf",
    signerName: input.signerName.trim(),
    signerTitle: input.signerTitle.trim(),
    institution: input.institution.trim(),
    additionalSigners: input.additionalSigners,
    signedAt,
    sourceHash,
    fingerprint: keys.fingerprint,
    algorithm: "RSA-PSS-2048-SHA256",
    verifyUrl: new URL(`/?documentId=${documentId}`, input.verifyBaseUrl ?? "http://localhost").toString(),
  };
  const payload: BrowserQrPayload = { ...metadata, metadataSignature: await signMetadata(metadata, keys.privateKey) };
  const payloadJson = JSON.stringify(payload);
  const qrText = `SV1:${toBase64Url(deflate(encoder.encode(payloadJson)))}`;
  const qrCode = await QRCode.toDataURL(qrText, {
    width: 800,
    margin: 4,
    errorCorrectionLevel: "M",
    color: { dark: "#102a43", light: "#ffffff" },
  });
  const qrPng = new Uint8Array(await (await fetch(qrCode)).arrayBuffer());

  const pdfDocument = await PDFDocument.load(sourcePdf, { updateMetadata: false });
  const sourcePageSize = pdfDocument.getPages()[0]?.getSize();
  const pageWidth = sourcePageSize && sourcePageSize.width >= 420 ? sourcePageSize.width : 595.28;
  const font = await pdfDocument.embedFont(StandardFonts.Helvetica);
  const boldFont = await pdfDocument.embedFont(StandardFonts.HelveticaBold);
  const margin = 42;
  const qrSize = Math.min(480, pageWidth - margin * 2);
  const qrImage = await pdfDocument.embedPng(qrPng);
  const signers = [
    { name: input.signerName, title: input.signerTitle },
    ...input.additionalSigners.filter((signer) => signer.name.trim() || signer.title.trim()),
  ];
  const fields: [string, string][] = [
    ["Signed at (UTC)", signedAt],
    ["Document ID", documentId],
    ["Source SHA-256", sourceHash],
    ["Key fingerprint", keys.fingerprint],
    ["Algorithm", "RSA-PSS / SHA-256 / 2048-bit"],
  ];
  const signerRowCount = Math.ceil(signers.length / 2);
  const signerRowHeight = 112;
  const basePageHeight = sourcePageSize && sourcePageSize.height >= 420 ? sourcePageSize.height : 841.89;
  const pageHeight = Math.max(basePageHeight, margin * 2 + 112 + signerRowCount * signerRowHeight + 24 + fields.length * 34 + 28 + qrSize + 15);
  const signaturePage = pdfDocument.addPage([pageWidth, pageHeight]);
  signaturePage.drawText("Verisign", { x: margin, y: pageHeight - 58, size: 17, font: boldFont, color: rgb(0.06, 0.16, 0.26) });
  signaturePage.drawText("DIGITAL SIGNATURE RECORD", { x: margin, y: pageHeight - 78, size: 8, font: boldFont, color: rgb(0.08, 0.48, 0.53) });
  const signerGap = 24;
  const signerColumnWidth = (pageWidth - margin * 2 - signerGap) / 2;
  for (const [index, signer] of signers.entries()) {
    const column = index % 2;
    const row = Math.floor(index / 2);
    const signerX = margin + column * (signerColumnWidth + signerGap);
    const signerY = pageHeight - 112 - row * signerRowHeight;
    const signerFields: [string, string][] = [
      [`Signer ${index + 1}`, signer.name],
      ["Title", signer.title],
      ["Institution", input.institution],
    ];
    signerFields.forEach(([label, value], fieldIndex) => {
      const labelY = signerY - fieldIndex * 34;
      signaturePage.drawText(label.toUpperCase(), { x: signerX, y: labelY, size: 6.5, font: boldFont, color: rgb(0.35, 0.48, 0.56) });
      signaturePage.drawText(safePdfText(value), { x: signerX, y: labelY - 12, size: 8.5, font, color: rgb(0.06, 0.16, 0.26), maxWidth: signerColumnWidth });
    });
  }
  let fieldY = pageHeight - 112 - signerRowCount * signerRowHeight - 24;
  for (const [label, value] of fields) {
    signaturePage.drawText(label.toUpperCase(), { x: margin, y: fieldY, size: 6.5, font: boldFont, color: rgb(0.35, 0.48, 0.56) });
    signaturePage.drawText(safePdfText(value), { x: margin, y: fieldY - 12, size: 8.5, font, color: rgb(0.06, 0.16, 0.26), maxWidth: pageWidth - margin * 2 });
    fieldY -= 34;
  }
  const qrX = (pageWidth - qrSize) / 2;
  const qrY = fieldY - 28 - qrSize;
  signaturePage.drawImage(qrImage, { x: qrX, y: qrY, width: qrSize, height: qrSize });
  const qrCaption = "SCAN TO VERIFY";
  signaturePage.drawText(qrCaption, { x: (pageWidth - boldFont.widthOfTextAtSize(qrCaption, 7)) / 2, y: qrY - 15, size: 7, font: boldFont, color: rgb(0.06, 0.42, 0.49) });

  const reason = `Verisign1:${toBase64Url(encoder.encode(payloadJson))}`;
  pdflibAddPlaceholder({
    pdfDoc: pdfDocument,
    pdfPage: signaturePage,
    reason,
    contactInfo: keys.fingerprint,
    name: safePdfText(input.signerName),
    location: safePdfText(input.institution),
    signingTime: new Date(signedAt),
    signatureLength: 4096,
    subFilter: "ETSI.CAdES.detached",
    widgetRect: [0, 0, 0, 0],
    appName: "Verisign",
  });

  const preparedPdf = await pdfDocument.save({ useObjectStreams: false, updateFieldAppearances: false });
  const certificate = await createSessionCertificate(keys.publicKeyObject, keys.privateKey, cryptoEngine);
  const finalized = await finalizePdf(preparedPdf, (bytes) => createCmsSignature(bytes, keys.privateKey, certificate, cryptoEngine));
  const publicKeyBytes = encoder.encode(keys.publicKey).length;

  return {
    signedPdf: finalized.pdf,
    sourceHash,
    signature: payload.metadataSignature,
    publicKey: keys.publicKey,
    fingerprint: keys.fingerprint,
    qrCode,
    qrPayload: payload,
    signedAt,
    documentId,
    algorithm: "RSA-PSS / SHA-256 / 2048-bit",
    sourceSize: sourcePdf.byteLength,
    signedSize: finalized.pdf.byteLength,
    signatureBytes: finalized.cmsBytes,
    publicKeyBytes,
  };
}