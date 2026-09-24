import QRCode from "qrcode";
import { deflateSync } from "node:zlib";

export const runtime = "nodejs";

export async function POST(request: Request) {
  try {
    const { data } = await request.json() as { data?: string };
    if (!data) return Response.json({ error: "QR data is required." }, { status: 400 });
    const compactData = `SV1:${deflateSync(Buffer.from(data, "utf8")).toString("base64url")}`;
    return Response.json({ dataUrl: await QRCode.toDataURL(compactData, { width: 640, margin: 4, errorCorrectionLevel: "M", color: { dark: "#102a43", light: "#ffffff" } }) });
  } catch { return Response.json({ error: "Unable to create QR code." }, { status: 400 }); }
}