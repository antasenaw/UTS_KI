# Verisign

Verisign adalah demo tanda tangan digital PDF. Aplikasi menggunakan RSA 2048-bit dengan RSA-PSS dan SHA-256, menambahkan halaman QR visual, lalu menandatangani PDF final dengan CMS `/ByteRange`.

## Menjalankan

```bash
npm install
npm run dev
```

Buka `http://localhost:3000`.

## Alur demo

1. Pilih PDF dan isi nama, jabatan, institusi, serta penanda tangan tambahan bila diperlukan.
2. Klik **Sign PDF**. Browser menambahkan halaman QR khusus dan membuat signature CMS menggunakan Web Crypto; private key tidak dikirim ke server.
3. Preview atau unduh satu PDF hasil signing; QR tampak pada halaman terakhir.
4. Buka **Verify Document** dan unggah PDF. Aplikasi merender halaman terakhir, memindai QR, dan memeriksa CMS signature serta metadata.
5. Buka **Tamper Demo** untuk menunjukkan perubahan satu byte/karakter, public key salah, QR palsu, dan QR berubah akan ditolak.
6. Buka **Test Results** atau jalankan `npm run benchmark` untuk hasil 30 trial.
7. Buka **History** untuk melihat hingga 20 dokumen yang baru ditandatangani; riwayat dapat dihapus dari browser.

Private key dibuat oleh Web Crypto sebagai `CryptoKey` non-exportable dan hanya disimpan sementara di memori tab browser. Signing PDF dan metadata berjalan di browser. Server menerima PDF final untuk memverifikasi CMS, memindai QR, dan mencocokkan metadata; server tidak menerima private key. Menutup atau memuat ulang tab menghilangkan kunci sesi, tetapi PDF yang sudah ditandatangani tetap dapat diverifikasi dari sertifikat publik yang tertanam.

## Hasil benchmark

Halaman Test Results mengukur 30 percobaan pada server dan menampilkan hasil mesin saat itu. Benchmark menggunakan kunci RSA sementara khusus benchmark, bukan private key sesi pengguna.

Jalankan `npm run dev` terlebih dahulu; `npm run benchmark` membaca endpoint benchmark lokal yang sama dengan halaman Test Results.

## Fitur yang tersedia

- Generasi pasangan kunci RSA 2048-bit
- Tanda tangan PDF CMS RSA-PSS/SHA-256 dengan `/ByteRange`
- Halaman signature tambahan dengan QR visual; tidak menimpa konten PDF asli
- Verifikasi invalid untuk dokumen yang diubah
- Verifikasi invalid untuk kunci publik yang salah
- QR berisi metadata penanda tangan, document ID, hash sumber, fingerprint, signature metadata, dan URL aplikasi
- Scan QR langsung dari render halaman terakhir PDF
- Private key non-exportable di browser; tidak dikirim ke endpoint aplikasi
- Benchmark 30 percobaan dengan ukuran PDF source/final, signature, key, tamper, wrong-key, dan fake-QR
- Integration test A–H: `npm test`
- Dukungan dua penandatangan pada satu dokumen melalui metadata QR
- Riwayat lokal hingga 20 dokumen menggunakan `localStorage`; hanya metadata, tanpa PDF/private key

## Catatan implementasi

PDF memakai sertifikat sesi self-signed. Signature membuktikan integritas dan keterkaitan dengan public key tersebut, tetapi tidak membuktikan identitas nyata penanda tangan atau status kepercayaan CA. Fitur ini adalah demonstrasi akademik, bukan layanan tanda tangan digital produksi. Kunci sesi tidak dapat dipulihkan setelah tab dimuat ulang/ditutup, dan PDF yang sudah memiliki signature sebelumnya belum didukung karena dokumen disimpan ulang sebelum ditandatangani. Web Crypto memerlukan HTTPS pada deployment (localhost diperbolehkan untuk pengembangan). Verifier server menerima isi PDF final; jangan mengunggah dokumen rahasia ke server yang tidak dipercaya.
