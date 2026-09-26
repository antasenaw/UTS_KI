declare module "jsqr" {
  type QRCode = {
    data: string;
    binaryData: number[];
    chunks: unknown[];
    version: number;
    location: unknown;
  };

  type Options = {
    inversionAttempts?: "dontInvert" | "onlyInvert" | "attemptBoth";
  };

  function jsQR(data: Uint8ClampedArray, width: number, height: number, options?: Options): QRCode | null;
  export default jsQR;
}
