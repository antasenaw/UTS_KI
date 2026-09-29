import { PDFDocument, StandardFonts } from "pdf-lib";
import { generateBrowserKeyPair } from "@/lib/browser-keys";
import { signPdfInBrowser } from "@/lib/browser-signature";
import { computeSHA256, generateRSAKeyPair, signData, verifyData } from "@/lib/crypto";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const TRIALS = 30;

export async function GET() {
  try {
    const sampleDocument = await PDFDocument.create();
    const samplePage = sampleDocument.addPage([612, 792]);
    const sampleFont = await sampleDocument.embedFont(StandardFonts.Helvetica);
    samplePage.drawText("Verisign 30-trial benchmark document", { x: 48, y: 720, size: 18, font: sampleFont });
    const pdf = Buffer.from(await sampleDocument.save());
    const hash = computeSHA256(pdf);
    const { publicKey, privateKey } = generateRSAKeyPair();
    const wrongPair = generateRSAKeyPair();
    const signingTimes: number[] = [];
    const verificationTimes: number[] = [];
    let signature = "";

    for (let trial = 0; trial < TRIALS; trial += 1) {
      const signStart = process.hrtime.bigint();
      signature = signData(hash, privateKey);
      signingTimes.push(Number(process.hrtime.bigint() - signStart) / 1_000_000);

      const verifyStart = process.hrtime.bigint();
      const valid = verifyData(hash, signature, publicKey);
      verificationTimes.push(Number(process.hrtime.bigint() - verifyStart) / 1_000_000);

      if (!valid) throw new Error(`Signature verification failed on trial ${trial + 1}.`);
    }

    const tamperedPdf = Buffer.from(pdf);
    tamperedPdf[0] = tamperedPdf[0] === 0x25 ? 0x24 : 0x25;
    const tamperedHash = computeSHA256(tamperedPdf);
    const tamperRejected = !verifyData(tamperedHash, signature, publicKey);
    const wrongKeyRejected = !verifyData(hash, signature, wrongPair.publicKey);
    const fakeQrHash = "fake-hash-value";
    const fakeQrRejected = !verifyData(fakeQrHash, signature, publicKey) && fakeQrHash !== hash;

    const benchmarkKeys = await generateBrowserKeyPair();
    const signedResult = await signPdfInBrowser(new Uint8Array(pdf), benchmarkKeys, {
      signerName: "Benchmark Signer",
      signerTitle: "Automated Tester",
      institution: "Verisign Benchmark",
      documentName: "benchmark.pdf",
      additionalSigners: [],
      verifyBaseUrl: "http://localhost",
    });

    const average = (values: number[]) => values.reduce((sum, value) => sum + value, 0) / values.length;

    return Response.json({
      trials: TRIALS,
      averageSigningMs: average(signingTimes),
      averageVerificationMs: average(verificationTimes),
      publicKeyBytes: Buffer.byteLength(publicKey, "utf8"),
      signatureBytes: Buffer.byteLength(signature, "base64"),
      encodedSignatureBytes: Buffer.byteLength(signature, "utf8"),
      cmsSignatureBytes: signedResult.signatureBytes,
      pdfBeforeBytes: pdf.byteLength,
      pdfAfterBytes: signedResult.signedSize,
      tests: {
        tamperRejected,
        wrongKeyRejected,
        fakeQrRejected,
      },
    });
  } catch (error) {
    console.error("Benchmark failed:", error);
    return Response.json({ error: "Unable to complete the benchmark." }, { status: 500 });
  }
}