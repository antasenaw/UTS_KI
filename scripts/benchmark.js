const baseUrl = process.env.BASE_URL ?? 'http://127.0.0.1:3000';

fetch(`${baseUrl}/api/benchmark`)
  .then(async (response) => {
    const result = await response.json();
    if (!response.ok) throw new Error(result.error ?? `Benchmark failed with ${response.status}`);

    console.log('=== Digital Signature PDF Benchmark ===');
    console.log(`Trials: ${result.trials}`);
    console.log(`Average signing time: ${result.averageSigningMs.toFixed(2)} ms`);
    console.log(`Average verification time: ${result.averageVerificationMs.toFixed(2)} ms`);
    console.log(`Public key PEM: ${result.publicKeyBytes} bytes`);
    console.log(`RSA signature: ${result.signatureBytes} bytes raw / ${result.encodedSignatureBytes} bytes Base64`);
    console.log(`CMS signature container: ${result.cmsSignatureBytes} bytes`);
    console.log(`PDF size: ${result.pdfBeforeBytes} bytes before / ${result.pdfAfterBytes} bytes signed`);
    console.log(`Tamper rejected: ${result.tests.tamperRejected}`);
    console.log(`Wrong key rejected: ${result.tests.wrongKeyRejected}`);
    console.log(`Fake QR rejected: ${result.tests.fakeQrRejected}`);
  })
  .catch((error) => {
    console.error(error instanceof Error ? error.message : 'Benchmark failed. Is the app running?');
    process.exitCode = 1;
  });
