"use client";

import { ChangeEvent, useEffect, useState } from "react";
import Image from "next/image";
import jsQR from "jsqr";
import { inflate } from "pako";
import { Activity, CheckCircle2, ChevronRight, CircleAlert, Clock3, CloudUpload, Copy, Download, FileCheck2, Fingerprint, KeyRound, LockKeyhole, QrCode, RefreshCw, ShieldCheck, TriangleAlert, Upload, XCircle } from "lucide-react";
import { generateBrowserKeyPair } from "@/lib/browser-keys";
import type { BrowserKeyPair } from "@/lib/browser-keys";
import { signPdfInBrowser } from "@/lib/browser-signature";


type AdditionalSigner = { name: string; title: string };
type SignerMetadata = { signerName: string; title: string; institution: string; additionalSigner: AdditionalSigner };
type QrPayload = { app: string; documentId: string; documentName: string; signerName: string; signerTitle: string; institution: string; additionalSigners: AdditionalSigner[]; signedAt: string; sourceHash: string; fingerprint: string; algorithm: string; verifyUrl: string; metadataSignature: string };
type DocumentRecord = { name: string; size: number; signedSize: number; hash: string; signature: string; publicKey: string; fingerprint: string; documentId: string; algorithm: string; qrCode?: string; signedAt: string } & SignerMetadata;
type HistoryEntry = { documentId: string; name: string; signerName: string; signedAt: string; fingerprint: string; hash: string; algorithm: string; size: number; signedSize: number };
type Verification = { valid: boolean; pdfSignatureValid: boolean; qrMatchesPdf: boolean; visualQrScanned: boolean; metadataValid: boolean; expectedKeyMatches: boolean; hash: string; sourceHash: string; fingerprint: string; documentId: string; signatureBytes: number };
type BenchmarkResult = { trials: number; averageSigningMs: number; averageVerificationMs: number; publicKeyBytes: number; signatureBytes: number; encodedSignatureBytes: number; cmsSignatureBytes: number; pdfBeforeBytes: number; pdfAfterBytes: number; tests: { tamperRejected: boolean; wrongKeyRejected: boolean; fakeQrRejected: boolean } };

const formatBytes = (bytes: number) => `${(bytes / 1024).toFixed(1)} KB`;
const shortHash = (value: string) => `${value.slice(0, 12)}...${value.slice(-8)}`;
const HISTORY_STORAGE_KEY = "Verisign.history.v1";
function readHistory(): HistoryEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const saved = JSON.parse(window.localStorage.getItem(HISTORY_STORAGE_KEY) ?? "[]") as unknown;
    if (!Array.isArray(saved)) return [];
    return saved.filter((entry): entry is HistoryEntry => entry && typeof entry === "object"
      && typeof entry.documentId === "string"
      && typeof entry.name === "string"
      && typeof entry.signerName === "string"
      && typeof entry.signedAt === "string"
      && typeof entry.fingerprint === "string"
      && typeof entry.hash === "string"
      && typeof entry.algorithm === "string"
      && typeof entry.size === "number"
      && typeof entry.signedSize === "number").slice(0, 20);
  } catch {
    return [];
  }
}
const toBase64 = (buffer: ArrayBuffer) => { let binary = ""; new Uint8Array(buffer).forEach((byte) => { binary += String.fromCharCode(byte); }); return btoa(binary); };
const decodeQrData = (value: string) => {
  if (!value.startsWith("SV1:")) return value;
  const encoded = value.slice(4).replace(/-/g, "+").replace(/_/g, "/");
  const padded = encoded.padEnd(Math.ceil(encoded.length / 4) * 4, "=");
  const binary = atob(padded);
  return inflate(Uint8Array.from(binary, (character) => character.charCodeAt(0)), { toText: true }) as string;
};

async function scanQrFromPdf(file: File, reportProgress: (message: string) => void = () => {}): Promise<QrPayload> {
  reportProgress("Rendering the final PDF page and scanning its QR...");
  const result = await request<Verification & { qrPayload?: QrPayload }>("/api/verify", { data: toBase64(await file.arrayBuffer()) });
  if (!result.visualQrScanned || !result.qrPayload) throw new Error("No readable Verisign QR was found in this PDF.");
  return result.qrPayload;
}

async function request<T>(url: string, body?: unknown): Promise<T> {
  const response = await fetch(url, { method: body ? "POST" : "GET", headers: body ? { "Content-Type": "application/json" } : undefined, body: body ? JSON.stringify(body) : undefined });
  if (!response.ok) {
    let message = "Request failed";
    try { message = (await response.json()).error ?? message; } catch { }
    throw new Error(message);
  }
  return response.json();
}

export default function Home() {
  const [keys, setKeys] = useState<BrowserKeyPair | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [signedFile, setSignedFile] = useState<File | null>(null);
  const [signedPdfUrl, setSignedPdfUrl] = useState("");
  const [documentRecord, setDocumentRecord] = useState<DocumentRecord | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>(readHistory);
  const [verification, setVerification] = useState<Verification | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [activeView, setActiveView] = useState<"dashboard" | "verify" | "detail" | "history" | "demo" | "results">("dashboard");
  const [copied, setCopied] = useState(false);
  const [signer, setSigner] = useState<SignerMetadata>({ signerName: "", title: "", institution: "", additionalSigner: { name: "", title: "" } });
  const [qrPayload, setQrPayload] = useState<QrPayload | null>(null);
  const [externalQrPayload, setExternalQrPayload] = useState<QrPayload | null>(null);
  const [qrFileName, setQrFileName] = useState("");
  const [qrLoading, setQrLoading] = useState(false);
  const [demoResult, setDemoResult] = useState<{ label: string; passed: boolean; message: string } | null>(null);
  const [benchmark, setBenchmark] = useState<BenchmarkResult | null>(null);
  const [benchmarkBusy, setBenchmarkBusy] = useState(false);

  useEffect(() => { void createKeys(); }, []);
  useEffect(() => () => { if (signedPdfUrl) URL.revokeObjectURL(signedPdfUrl); }, [signedPdfUrl]);
  useEffect(() => {
    try {
      localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(history));
    } catch { }
  }, [history]);

  const status = verification?.valid ? "VALID" : verification ? "INVALID" : "READY";
  const statusClass = verification?.valid ? "status-valid" : verification ? "status-invalid" : "status-ready";
  async function createKeys() {
    setBusy(true); setNotice("");
    try { setKeys(await generateBrowserKeyPair()); setDocumentRecord(null); setSignedFile(null); setSignedPdfUrl(""); setQrPayload(null); setExternalQrPayload(null); setVerification(null); setDemoResult(null); setNotice("New non-exportable RSA-2048 key pair generated in this browser session."); }
    catch (error) { setNotice(error instanceof Error ? error.message : "Could not generate keys."); }
    finally { setBusy(false); }
  }

  async function signDocument() {
    if (!file || !keys) return;
    if (!signer.signerName.trim() || !signer.title.trim() || !signer.institution.trim()) { setNotice("Signer name, title, and institution are required."); return; }
    if (file.size > 25 * 1024 * 1024) { setNotice("PDF exceeds the 25 MB signing limit."); return; }
    setBusy(true); setVerification(null); setDemoResult(null); setNotice("");
    try {
      const buffer = await file.arrayBuffer();
      if (new TextDecoder().decode(buffer.slice(0, 5)) !== "%PDF-") throw new Error("Only valid PDF files can be signed.");
      const result = await signPdfInBrowser(new Uint8Array(buffer), keys, { signerName: signer.signerName, signerTitle: signer.title, institution: signer.institution, additionalSigners: [signer.additionalSigner], documentName: file.name, verifyBaseUrl: window.location.origin });
      const signedBytes = new Uint8Array(result.signedPdf);
      const signedName = `${file.name.replace(/\.pdf$/i, "")}.signed.pdf`;
      const outputFile = new File([signedBytes.buffer as ArrayBuffer], signedName, { type: "application/pdf" });
      setSignedPdfUrl(URL.createObjectURL(outputFile));
      const record: DocumentRecord = { name: file.name, size: result.sourceSize, signedSize: result.signedSize, hash: result.sourceHash, signature: result.signature, publicKey: result.publicKey, fingerprint: result.fingerprint, documentId: result.documentId, algorithm: result.algorithm, qrCode: result.qrCode, signedAt: result.signedAt, ...signer };
      setSignedFile(outputFile); setQrPayload(result.qrPayload); setExternalQrPayload(null); setDocumentRecord(record);
      const historyEntry: HistoryEntry = { documentId: result.documentId, name: file.name, signerName: signer.signerName.trim(), signedAt: result.signedAt, fingerprint: result.fingerprint, hash: result.sourceHash, algorithm: result.algorithm, size: result.sourceSize, signedSize: result.signedSize };
      setHistory((current) => [historyEntry, ...current.filter((entry) => entry.documentId !== historyEntry.documentId)].slice(0, 20));
      setNotice("PDF ditandatangani di perangkat ini. Private key tidak dikirim ke server.");
    } catch (error) { setNotice(error instanceof Error ? error.message : "Could not sign document."); }
    finally { setBusy(false); }
  }

  function downloadSignedPdf() {
    if (!signedFile) return;
    const url = URL.createObjectURL(signedFile);
    const link = document.createElement("a");
    link.href = url;
    link.download = signedFile.name;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function loadBenchmark() {
    setBenchmarkBusy(true);
    setNotice("");
    try {
      const result = await request<BenchmarkResult>("/api/benchmark");
      setBenchmark(result);
      setNotice(`Benchmark selesai: ${result.trials} percobaan.`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Benchmark gagal dijalankan.");
    } finally {
      setBenchmarkBusy(false);
    }
  }

  async function verifyDocument(testFile = signedFile ?? file, expectedPublicKey?: string, payload = qrPayload) {
    if (!testFile) return null;
    const buffer = await testFile.arrayBuffer();
    const result = await request<Verification>("/api/verify", { data: toBase64(buffer), qrPayload: payload, publicKey: expectedPublicKey });
    setVerification(result); return result;
  }

  async function runTamperTest() {
    const signedPdf = signedFile ?? file;
    if (!documentRecord || !signedPdf) return;
    try {
      const tamperedBytes = new Uint8Array(await signedPdf.arrayBuffer());
      tamperedBytes[10] ^= 1;
      const tampered = new File([tamperedBytes], signedPdf.name, { type: signedPdf.type });
      const result = await verifyDocument(tampered, undefined, qrPayload);
      const passed = Boolean(result && !result.valid);
      setDemoResult({ label: "Tamper test", passed, message: passed ? "A one-byte change to the signed PDF was rejected." : "The changed document was incorrectly accepted." });
      setActiveView("demo"); setNotice(passed ? "Tamper test passed: verification returned INVALID." : "Tamper test failed: verification returned VALID.");
    } catch (error) { setNotice(error instanceof Error ? error.message : "Tamper test failed."); }
  }

  async function runWrongKeyTest() {
    const signedPdf = signedFile ?? file;
    if (!documentRecord || !signedPdf) return;
    try {
      const wrong = await generateBrowserKeyPair();
      const result = await verifyDocument(signedPdf, wrong.publicKey, qrPayload);
      const passed = Boolean(result && !result.valid);
      setDemoResult({ label: "Wrong-key test", passed, message: passed ? "The unrelated public key was rejected." : "The unrelated public key was incorrectly accepted." });
      setActiveView("demo"); setNotice(passed ? "Wrong-key test passed: verification returned INVALID." : "Wrong-key test failed: verification returned VALID.");
    } catch (error) { setNotice(error instanceof Error ? error.message : "Wrong-key test failed."); }
  }

  async function runFakeQrTest() {
    const signedPdf = signedFile ?? file;
    if (!documentRecord || !signedPdf || !qrPayload) { setNotice("Sign or upload a signed PDF before running the fake QR test."); return; }
    const fakeQrPayload = { ...qrPayload, signerName: "Forged Signer" };
    try {
      const result = await verifyDocument(signedPdf, undefined, fakeQrPayload);
      const passed = Boolean(result && !result.valid && !result.qrMatchesPdf);
      setDemoResult({ label: "Fake QR test", passed, message: passed ? "The fabricated QR hash was rejected." : "The fabricated QR payload was incorrectly accepted." });
      setActiveView("demo"); setNotice(passed ? "Fake QR test passed: the fabricated payload was rejected." : "Fake QR test failed: the fabricated payload was accepted.");
    } catch (error) { setNotice(error instanceof Error ? error.message : "Fake QR test failed."); }
  }

  async function onQrImageChange(event: ChangeEvent<HTMLInputElement>) {
    const qrFile = event.target.files?.[0];
    if (!qrFile) return;
    setQrFileName(qrFile.name); setQrPayload(null); setExternalQrPayload(null); setQrLoading(true); setNotice(`QR image selected: ${qrFile.name}. Reading QR data...`);
    try {
      const imageUrl = URL.createObjectURL(qrFile);
      const image = new window.Image();
      image.onload = () => {
        try {
          const canvas = document.createElement("canvas");
          const scale = Math.max(1, 800 / Math.max(image.naturalWidth, image.naturalHeight));
          canvas.width = Math.round(image.naturalWidth * scale); canvas.height = Math.round(image.naturalHeight * scale);
          const context = canvas.getContext("2d");
          if (!context) { setNotice("QR scanner is unavailable in this browser."); return; }
          context.imageSmoothingEnabled = false; context.drawImage(image, 0, 0, canvas.width, canvas.height);
          const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
          const result = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "attemptBoth" });
          if (!result) { setNotice("Image uploaded, but no readable QR code was found. Use the original downloaded QR image."); return; }
          const payload = JSON.parse(decodeQrData(result.data)) as QrPayload;
          if (payload.app !== "Verisign" || !payload.documentId || !payload.metadataSignature || !payload.sourceHash || !payload.fingerprint || !payload.signerName || !payload.signerTitle || !payload.institution || !payload.signedAt) { setNotice("Image uploaded, but this is not a valid Verisign QR record."); return; }
          setQrPayload(payload); setExternalQrPayload(payload); setNotice(`QR loaded for ${payload.documentName}. Select the matching PDF, then verify it.`);
        } catch (error) { setNotice(error instanceof Error ? error.message : "Could not read the QR code."); }
        finally { setQrLoading(false); URL.revokeObjectURL(imageUrl); }
      };
      image.onerror = () => { setQrLoading(false); URL.revokeObjectURL(imageUrl); setNotice("Could not read the QR image."); };
      image.src = imageUrl;
    } catch (error) { setQrLoading(false); setNotice(error instanceof Error ? error.message : "Could not read the QR code."); }
  }

  async function verifyQrPayload() {
    if (!file) { setNotice("Upload the signed PDF first."); return; }
    if (qrLoading) { setNotice("Please wait while the QR image is being read."); return; }
    try {
      const result = await verifyDocument(file, undefined, qrPayload);
      setNotice(result?.valid ? "VALID: PDF signature and embedded QR metadata match." : "INVALID: PDF signature, QR payload, metadata, or key did not match.");
    } catch (error) { setNotice(error instanceof Error ? error.message : "QR verification failed."); }
  }

  async function openVerifyView() {
    setActiveView("verify");
    const candidate = signedFile ?? file;
    if (!candidate) return;
    setFile(candidate); setQrLoading(true); setNotice("Scanning the QR from the final PDF page...");
    try {
      const embeddedPayload = await scanQrFromPdf(candidate, setNotice);
      if (!externalQrPayload) setQrPayload(embeddedPayload);
      setNotice(externalQrPayload ? "Embedded QR scanned. The uploaded QR image will be compared with this PDF." : "Embedded QR scanned. Verify the signed PDF to continue.");
    }
    catch (error) { setQrPayload(null); setNotice(error instanceof Error ? error.message : "Could not scan a QR from this PDF."); }
    finally { setQrLoading(false); }
  }

  async function onFileChange(event: ChangeEvent<HTMLInputElement>) {
    const nextFile = event.target.files?.[0];
    if (!nextFile) return;
    const retainedExternalQr = activeView === "verify" ? externalQrPayload : null;
    setFile(nextFile); setSignedFile(null); setSignedPdfUrl(""); setDocumentRecord(null); setQrPayload(retainedExternalQr); setVerification(null); setDemoResult(null); setNotice("");
    if (!retainedExternalQr) setExternalQrPayload(null);
    if (activeView === "verify" && nextFile.type === "application/pdf") {
      setQrLoading(true);
      try {
        const payload = await scanQrFromPdf(nextFile, setNotice);
        if (!retainedExternalQr) setQrPayload(payload);
        setNotice(retainedExternalQr ? `Embedded QR scanned. Comparing against ${retainedExternalQr.documentName}.` : `Embedded QR scanned from ${payload.documentName}.`);
      }
      catch (error) { setNotice(error instanceof Error ? error.message : "Could not scan a QR from this PDF."); }
      finally { setQrLoading(false); }
    }
  }
  async function copyPublicKey() { if (!keys) return; await navigator.clipboard.writeText(keys.publicKey); setCopied(true); setTimeout(() => setCopied(false), 1600); }
  function clearHistory() {
    setHistory([]);
    setNotice("Riwayat lokal dihapus dari browser ini.");
  }

  return <main className="shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Fingerprint size={21} /></div><div><strong>Verisign</strong><span>Digital trust, simplified.</span></div></div>
      <nav className="nav-list">
        <button className={activeView === "dashboard" ? "nav-item active" : "nav-item"} onClick={() => setActiveView("dashboard")}><ShieldCheck size={18} /> Dashboard</button>
        <button className={activeView === "verify" ? "nav-item active" : "nav-item"} onClick={() => void openVerifyView()}><FileCheck2 size={18} /> Verify Document</button>
        <button className={activeView === "detail" ? "nav-item active" : "nav-item"} onClick={() => setActiveView("detail")}><LockKeyhole size={18} /> Document Detail</button>
        <button className={activeView === "history" ? "nav-item active" : "nav-item"} onClick={() => setActiveView("history")}><Clock3 size={18} /> History</button>
        <button className={activeView === "demo" ? "nav-item active" : "nav-item"} onClick={() => setActiveView("demo")}><TriangleAlert size={18} /> Tamper Demo</button>
        <button className={activeView === "results" ? "nav-item active" : "nav-item"} onClick={() => { setActiveView("results"); if (!benchmark) void loadBenchmark(); }}><Activity size={18} /> Test Results</button>
      </nav>
      <div className="sidebar-note"><div className="online-dot" /> Browser key custody<span>Private key is non-exportable and remains in this browser session.</span></div>
    </aside>
    <section className="content">
      <header className="topbar"><div><span className="eyebrow">SECURE WORKSPACE / 01</span><h1>{activeView === "dashboard" ? "Document dashboard" : activeView === "verify" ? "Verify document" : activeView === "detail" ? "Document detail" : activeView === "history" ? "Signing history" : activeView === "results" ? "Test results" : "Tamper test lab"}</h1></div><div className="session-pill"><span className="online-dot" /> Session active</div></header>
      {notice && <div className="notice"><CircleAlert size={17} /> {notice}</div>}
      {activeView === "results" && benchmark && <div className="benchmark-size-strip"><div><span>PDF BEFORE SIGNING</span><strong>{benchmark.pdfBeforeBytes} bytes</strong></div><div><span>SIGNED PDF</span><strong>{benchmark.pdfAfterBytes} bytes</strong></div><div><span>CMS SIGNATURE CONTAINER</span><strong>{benchmark.cmsSignatureBytes} bytes</strong></div></div>}
      {activeView === "dashboard" && <>
        <section className="hero-panel"><div><span className="eyebrow cyan">END-TO-END SIGNING</span><h2>Make every document<br /><em>verifiably yours.</em></h2><p>Hash a PDF, sign it with RSA-PSS, and share proof that anyone can verify.</p><div className="hero-actions"><label className="button primary"><Upload size={17} /> Choose PDF<input type="file" accept="application/pdf,.pdf" onChange={onFileChange} /></label><button className="button ghost" onClick={() => void openVerifyView()}><QrCode size={17} /> Verify with QR</button></div></div><div className="hero-graphic"><div className="orbit orbit-one" /><div className="orbit orbit-two" /><div className="core-shield"><ShieldCheck size={43} /></div><span className="graphic-label label-a">RSA-PSS 2048</span><span className="graphic-label label-b">SHA-256</span></div></section>
        <section className="crypto-panel">
  <div className="crypto-panel-header">
    <div>
      <span className="eyebrow cyan">CRYPTOGRAPHIC IDENTITY</span>
      <h3>RSA & SHA-256</h3>
      <p>
        Algoritma kriptografi yang digunakan untuk membuat dan memverifikasi
        tanda tangan digital dokumen.
      </p>
    </div>

    <div className="crypto-status">
      <span className="online-dot" />
      {keys ? "KEY READY" : "GENERATING KEY"}
    </div>
  </div>

  <div className="crypto-grid">

    <div className="crypto-card">
      <div className="crypto-card-icon">
        <KeyRound size={19} />
      </div>

      <div>
        <span>KEY ALGORITHM</span>
        <strong>RSA-2048</strong>
        <small>
          2048-bit RSA key pair
        </small>
      </div>
    </div>

    <div className="crypto-card">
      <div className="crypto-card-icon">
        <ShieldCheck size={19} />
      </div>

      <div>
        <span>SIGNATURE ALGORITHM</span>
        <strong>RSA-PSS</strong>
        <small>
          RSA Probabilistic Signature Scheme
        </small>
      </div>
    </div>

    <div className="crypto-card">
      <div className="crypto-card-icon">
        <Fingerprint size={19} />
      </div>

      <div>
        <span>HASH ALGORITHM</span>
        <strong>SHA-256</strong>
        <small>
          Secure document fingerprint
        </small>
      </div>
    </div>

  </div>

  <div className="crypto-fingerprint">
    <div>
      <span>PUBLIC KEY FINGERPRINT</span>

      <code>
        {keys
          ? keys.fingerprint
          : "Generating secure session key..."}
      </code>
    </div>

    <button
      className="icon-button"
      title="Copy public key"
      onClick={copyPublicKey}
      disabled={!keys}
    >
      <Copy size={17} />
    </button>
  </div>

  <div className="crypto-footer">
    <span>
      <LockKeyhole size={15} />
      Private key is non-exportable and stays in this browser session.
    </span>

    <button
      className="button ghost"
      onClick={createKeys}
      disabled={busy}
    >
      <RefreshCw size={15} />
      Generate new key
    </button>
  </div>
</section>
        <div className="section-heading"><div><span className="eyebrow">WORKFLOW</span><h3>Sign a document</h3></div><span className="step-count">STEP 01 / 03</span></div>
        <details className="metadata-details"><summary>Signer information</summary><div className="metadata-fields"><label>Signer name<input value={signer.signerName} onChange={(event) => setSigner({ ...signer, signerName: event.target.value })} /></label><label>Title<input value={signer.title} onChange={(event) => setSigner({ ...signer, title: event.target.value })} /></label><label>Institution<input value={signer.institution} onChange={(event) => setSigner({ ...signer, institution: event.target.value })} /></label><label>Additional signer<input value={signer.additionalSigner.name} onChange={(event) => setSigner({ ...signer, additionalSigner: { ...signer.additionalSigner, name: event.target.value } })} /></label><label>Additional signer title<input value={signer.additionalSigner.title} onChange={(event) => setSigner({ ...signer, additionalSigner: { ...signer.additionalSigner, title: event.target.value } })} /></label></div></details>
        <section className="workspace-grid"><div className="upload-card"><div className="card-top"><div className="icon-box"><CloudUpload size={20} /></div><span className="file-type">PDF ONLY</span></div><h3>{file ? file.name : "Drop your document here"}</h3><p>{file ? `${formatBytes(file.size)} selected and ready to sign.` : "Upload a PDF to calculate its fingerprint and create a signature."}</p><label className="dropzone"><Upload size={19} /><span>{file ? "Choose a different PDF" : "Browse files"}</span><input type="file" accept="application/pdf,.pdf" onChange={onFileChange} /></label>{file && <div className="selected-file"><FileCheck2 size={17} /><span>{file.name}</span><b>{formatBytes(file.size)}</b></div>}<button className="button primary full" disabled={!file || !keys || busy} onClick={signDocument}>{busy ? <RefreshCw className="spin" size={17} /> : <LockKeyhole size={17} />} {busy ? "Signing securely..." : "Sign PDF"}<ChevronRight size={16} /></button></div><div className="result-card"><div className="card-top"><div className="icon-box green"><CheckCircle2 size={20} /></div><span className={"status-badge " + statusClass}>{status}</span></div><h3>{documentRecord ? "PDF berhasil ditandatangani" : "Your signature result"}</h3>{documentRecord ? <><div className="hash-row"><span>DOCUMENT HASH</span><code>{shortHash(documentRecord.hash)}</code></div><div className="hash-row"><span>KEY FINGERPRINT</span><code>{documentRecord.fingerprint}</code></div><div className="qr-preview">{documentRecord.qrCode && <Image src={documentRecord.qrCode} alt="Embedded verification QR preview" width={104} height={104} unoptimized />}<div><strong>QR tertanam di PDF</strong><span>Halaman verifikasi ditambahkan tanpa menutupi isi halaman asli.</span></div></div><button className="button primary full" onClick={downloadSignedPdf}><Download size={17} /> Download signed PDF</button>{signedPdfUrl && <a className="button ghost full" href={signedPdfUrl} target="_blank" rel="noreferrer"><FileCheck2 size={17} /> Preview signed PDF</a>}<button className="button dark full" onClick={() => setActiveView("detail")}>Open document detail <ChevronRight size={16} /></button></> : <div className="empty-result"><QrCode size={34} /><span>Your signed document and embedded QR will appear here.</span></div>}</div></section>
        <section className="security-strip"><div><KeyRound size={19} /><span><strong>RSA-2048 key pair</strong><small>{keys ? `Fingerprint ${keys.fingerprint}` : "Generating secure session keys..."}</small></span></div><button className="icon-button" title="Generate new key pair" onClick={createKeys} disabled={busy}><RefreshCw size={17} /></button><button className="icon-button" title="Copy public key" onClick={copyPublicKey} disabled={!keys}><Copy size={17} /></button>{copied && <span className="copied">Copied</span>}</section>
      </>}
      {activeView === "verify" && <section className="wide-panel"><div className="panel-heading"><div className="icon-box"><QrCode size={20} /></div><div><span className="eyebrow">PDF SIGNATURE VERIFICATION</span><h2>Verify the signed PDF</h2></div></div><p className="panel-copy">Upload the signed PDF. Verisign renders its final page, scans the embedded QR, then validates the PDF CMS signature and signed metadata. A separate QR image is optional.</p><label className="dropzone large"><Upload size={22} /><span>{file ? file.name : "Choose a signed PDF"}</span><small>{qrPayload ? `Embedded QR scanned: ${qrPayload.documentId}` : "The last page QR will be scanned automatically"}</small><input type="file" accept="application/pdf,.pdf" onChange={onFileChange} /></label><label className="dropzone large"><QrCode size={22} /><span>{qrPayload ? `QR loaded: ${qrPayload.documentName}` : qrFileName || "Optional: upload a QR image"}</span><small>{qrPayload ? "QR payload ready for comparison" : qrFileName ? "Reading QR image..." : "Use this only if scanning a QR screenshot separately"}</small><input type="file" accept="image/*" onChange={onQrImageChange} /></label><button className="button primary" disabled={busy || qrLoading || !file} onClick={() => void verifyQrPayload()}><ShieldCheck size={17} /> Verify PDF + QR signature</button>{verification && <div className={verification.valid ? "verification-result valid" : "verification-result invalid"}>{verification.valid ? <CheckCircle2 size={26} /> : <XCircle size={26} />}<div><strong>{verification.valid ? "VALID SIGNATURE" : "INVALID SIGNATURE"}</strong><span>{verification.valid ? "PDF ByteRange signature and QR metadata both verified." : "PDF signature, QR payload, metadata, or public key is invalid."}</span></div></div>}</section>}
      {activeView === "detail" && <section className="wide-panel"><div className="panel-heading"><div className="icon-box green"><FileCheck2 size={20} /></div><div><span className="eyebrow">SIGNED RECORD</span><h2>{documentRecord?.name ?? "No document signed yet"}</h2></div></div>{documentRecord ? <div className="detail-layout"><div className="detail-list"><div><span>STATUS</span><strong className="text-green"><CheckCircle2 size={16} /> Signature valid</strong></div><div><span>SOURCE SHA-256</span><code>{documentRecord.hash}</code></div><div><span>DOCUMENT ID</span><code>{documentRecord.documentId}</code></div><div><span>RSA PUBLIC KEY FINGERPRINT</span><code>{documentRecord.fingerprint}</code></div><div><span>SIGNED AT</span><strong>{new Date(documentRecord.signedAt).toLocaleString()}</strong></div><div><span>ALGORITHM</span><strong>{documentRecord.algorithm}</strong></div><div><span>PDF SIZE</span><strong>{formatBytes(documentRecord.size)} before / {formatBytes(documentRecord.signedSize)} signed</strong></div><div><span>PDF SIGNATURE</span><strong>CMS detached / ByteRange</strong></div></div><div className="qr-large"><Image src={documentRecord.qrCode ?? ""} alt="Embedded QR code for document verification" width={220} height={220} unoptimized /><span>QR is embedded on the final PDF page</span><button className="button primary" onClick={downloadSignedPdf}><Download size={16} /> Download signed PDF</button>{signedPdfUrl && <a className="button ghost" href={signedPdfUrl} target="_blank" rel="noreferrer"><FileCheck2 size={16} /> Preview signed PDF</a>}<button className="button ghost" onClick={() => { const link = document.createElement("a"); link.href = documentRecord.qrCode ?? ""; link.download = "Verisign-qr.png"; link.click(); }}><Download size={16} /> Download QR copy</button></div></div> : <div className="empty-result"><FileCheck2 size={34} /><span>Sign a PDF from the dashboard to see its details.</span></div>}</section>}
      {activeView === "history" && <section className="wide-panel"><div className="history-heading"><div className="panel-heading"><div className="icon-box"><Clock3 size={20} /></div><div><span className="eyebrow">THIS BROWSER</span><h2>Recent signatures</h2></div></div><button className="button ghost" disabled={!history.length} onClick={clearHistory}><XCircle size={16} /> Clear history</button></div><p className="panel-copy">Riwayat menyimpan metadata di browser ini saja. File PDF dan private key tidak disimpan.</p>{history.length ? <div className="history-list">{history.map((entry) => <article className="history-row" key={entry.documentId}><div className="history-file"><FileCheck2 size={18} /><div><strong title={entry.name}>{entry.name}</strong><span>{entry.signerName} · {new Date(entry.signedAt).toLocaleString()}</span></div></div><div className="history-meta"><span>FINGERPRINT</span><code>{entry.fingerprint}</code></div><div className="history-meta"><span>SHA-256</span><code>{shortHash(entry.hash)}</code></div><div className="history-meta history-size"><span>PDF SIZE</span><strong>{formatBytes(entry.size)} / {formatBytes(entry.signedSize)}</strong></div></article>)}</div> : <div className="empty-result"><Clock3 size={32} /><span>Belum ada dokumen yang ditandatangani di browser ini.</span></div>}</section>}
      {activeView === "demo" && <section className="wide-panel"><div className="panel-heading"><div className="icon-box amber"><TriangleAlert size={20} /></div><div><span className="eyebrow">DEMO MODE</span><h2>Break the signature on purpose</h2></div></div><p className="panel-copy">Use these tests to demonstrate why a signature is meaningful: a modified PDF, a fabricated QR payload, or an unrelated public key must all fail verification.</p><div className="test-grid"><div className="test-card"><div className="test-number">01</div><h3>Tampered document</h3><p>Flips exactly one byte in the signed PDF, then checks its CMS ByteRange signature.</p><button className="button dark" disabled={!documentRecord || !file || busy} onClick={runTamperTest}><TriangleAlert size={16} /> Run tamper test</button></div><div className="test-card"><div className="test-number">02</div><h3>Wrong public key</h3><p>Generates a fresh RSA key and verifies the signed PDF with the wrong public key.</p><button className="button dark" disabled={!documentRecord || !file || busy} onClick={runWrongKeyTest}><KeyRound size={16} /> Test wrong key</button></div><div className="test-card"><div className="test-number">03</div><h3>Fake QR payload</h3><p>Alters QR signer metadata and checks it against the signed PDF signature dictionary.</p><button className="button dark" disabled={!documentRecord || !file || busy} onClick={runFakeQrTest}><QrCode size={16} /> Test fake QR</button></div></div>{demoResult && <div className={demoResult.passed ? "verification-result valid" : "verification-result invalid"}>{demoResult.passed ? <CheckCircle2 size={26} /> : <XCircle size={26} />}<div><strong>{demoResult.passed ? `${demoResult.label.toUpperCase()} PASSED` : `${demoResult.label.toUpperCase()} FAILED`}</strong><span>{demoResult.message}</span></div></div>}</section>}
      {activeView === "results" && <section className="wide-panel"><div className="panel-heading"><div className="icon-box"><Activity size={20} /></div><div><span className="eyebrow">RSA-PSS / SHA-256</span><h2>Benchmark results</h2></div><button className="button primary benchmark-action" disabled={benchmarkBusy} onClick={() => void loadBenchmark()}>{benchmarkBusy ? <RefreshCw className="spin" size={16} /> : <RefreshCw size={16} />} Run {benchmark?.trials ?? 30} trials</button></div><p className="panel-copy">Measurements run on this server with a generated RSA-2048 key pair. Negative tests verify that altered input is rejected.</p>{benchmarkBusy && <div className="benchmark-loading">Running 30 signing and verification trials...</div>}{benchmark && !benchmarkBusy && <><div className="benchmark-metrics"><div><span>AVERAGE SIGNING</span><strong>{benchmark.averageSigningMs.toFixed(2)}<small> ms</small></strong></div><div><span>AVERAGE VERIFICATION</span><strong>{benchmark.averageVerificationMs.toFixed(2)}<small> ms</small></strong></div><div><span>PUBLIC KEY PEM</span><strong>{benchmark.publicKeyBytes}<small> bytes</small></strong></div><div><span>SIGNATURE</span><strong>{benchmark.signatureBytes}<small> bytes raw</small></strong><small className="metric-note">{benchmark.encodedSignatureBytes} bytes Base64</small></div></div><div className="benchmark-chart"><h3>Average operation time</h3><div className="benchmark-bar-row"><span>Signing</span><div className="benchmark-bar-track"><div className="benchmark-bar signing" style={{ width: `${Math.max(2, benchmark.averageSigningMs / Math.max(benchmark.averageSigningMs, benchmark.averageVerificationMs) * 100)}%` }} /></div><code>{benchmark.averageSigningMs.toFixed(2)} ms</code></div><div className="benchmark-bar-row"><span>Verify</span><div className="benchmark-bar-track"><div className="benchmark-bar verifying" style={{ width: `${Math.max(2, benchmark.averageVerificationMs / Math.max(benchmark.averageSigningMs, benchmark.averageVerificationMs) * 100)}%` }} /></div><code>{benchmark.averageVerificationMs.toFixed(2)} ms</code></div></div><div className="benchmark-test-results"><h3>Security scenarios <small>({benchmark.trials} trials)</small></h3>{[["Single-character tamper", benchmark.tests.tamperRejected], ["Wrong public key", benchmark.tests.wrongKeyRejected], ["Fake QR hash", benchmark.tests.fakeQrRejected]].map(([label, passed]) => <div className="benchmark-test-row" key={String(label)}><span>{label}</span><strong className={passed ? "text-green" : "text-red"}>{passed ? "REJECTED" : "NOT REJECTED"}</strong></div>)}</div></>}</section>}
    </section>
  </main>;
}
