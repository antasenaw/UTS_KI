import type { BrowserKeyPair } from "./browser-keys";

const DATABASE_NAME = "verisign-workspace";
const STORE_NAME = "files";
const SIGNED_PDF_KEY = "signed-pdf";
const KEY_PAIR_KEY = "browser-key-pair";

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE_NAME);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Could not open local file storage."));
  });
}

export async function saveSignedPdf(file: File): Promise<void> {
  const database = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      transaction.objectStore(STORE_NAME).put(file, SIGNED_PDF_KEY);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error("Could not save the signed PDF locally."));
      transaction.onabort = () => reject(transaction.error ?? new Error("Saving the signed PDF was cancelled."));
    });
  } finally {
    database.close();
  }
}

export async function loadSignedPdf(): Promise<File | null> {
  const database = await openDatabase();
  try {
    return await new Promise<File | null>((resolve, reject) => {
      const request = database.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(SIGNED_PDF_KEY);
      request.onsuccess = () => {
        if (request.result instanceof File) resolve(request.result);
        else if (request.result instanceof Blob) resolve(new File([request.result], "signed.pdf", { type: request.result.type || "application/pdf" }));
        else resolve(null);
      };
      request.onerror = () => reject(request.error ?? new Error("Could not load the signed PDF from local storage."));
    });
  } finally {
    database.close();
  }
}

export async function saveBrowserKeyPair(keyPair: BrowserKeyPair): Promise<void> {
  const database = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      transaction.objectStore(STORE_NAME).put(keyPair, KEY_PAIR_KEY);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error("Could not save the browser key pair."));
      transaction.onabort = () => reject(transaction.error ?? new Error("Saving the browser key pair was cancelled."));
    });
  } finally {
    database.close();
  }
}

export async function loadBrowserKeyPair(): Promise<BrowserKeyPair | null> {
  const database = await openDatabase();
  try {
    return await new Promise<BrowserKeyPair | null>((resolve, reject) => {
      const request = database.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(KEY_PAIR_KEY);
      request.onsuccess = () => {
        const value = request.result as BrowserKeyPair | undefined;
        resolve(value?.privateKey && value.publicKeyObject && value.publicKey && value.fingerprint ? value : null);
      };
      request.onerror = () => reject(request.error ?? new Error("Could not load the browser key pair."));
    });
  } finally {
    database.close();
  }
}
