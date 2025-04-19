export default {
  async fetch(request: Request): Promise<Response> {
    if (request.method !== "PUT") {
      return new Response("Only PUT requests are allowed", { status: 405 });
    }

    const url = new URL(request.url);
    const objectKey = url.searchParams.get("filename");
    if (!objectKey) {
      return new Response("Missing filename", { status: 400 });
    }

    const accountId = R2_ACCOUNT_ID;
    const bucket = R2_BUCKET;
    const accessKeyId = R2_ACCESS_KEY;
    const secretAccessKey = R2_SECRET_KEY;

    const endpoint = `https://${accountId}.r2.cloudflarestorage.com`;
    const targetUrl = `${endpoint}/${bucket}/${objectKey}`;

    // Get the body of the incoming PUT request
    const body = await request.arrayBuffer();

    // Generate the required headers
    const now = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
    const datestamp = now.slice(0, 8);
    const amzDate = now;

    const region = "auto";
    const service = "s3";
    const host = `${accountId}.r2.cloudflarestorage.com`;
    const credentialScope = `${datestamp}/${region}/${service}/aws4_request`;

    const headers = {
      "host": host,
      "x-amz-date": amzDate,
      "x-amz-content-sha256": await hashHex(body),
    };

    const signedHeaders = Object.keys(headers).sort().join(";");

    const canonicalRequest = [
      "PUT",
      `/${bucket}/${objectKey}`,
      "",
      Object.entries(headers).sort().map(([k, v]) => `${k}:${v}`).join("\n") + "\n",
      signedHeaders,
      headers["x-amz-content-sha256"]
    ].join("\n");

    const stringToSign = [
      "AWS4-HMAC-SHA256",
      amzDate,
      credentialScope,
      await hashHex(canonicalRequest),
    ].join("\n");

    const signingKey = await getSignatureKey(secretAccessKey, datestamp, region, service);
    const signature = await hmacHex(signingKey, stringToSign);

    const authHeader = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    // Final headers to send to R2
    const r2Headers = new Headers(headers);
    r2Headers.set("Authorization", authHeader);

    // Perform the actual upload
    const uploadRes = await fetch(targetUrl, {
      method: "PUT",
      headers: r2Headers,
      body: body,
    });

    if (!uploadRes.ok) {
      return new Response("Upload failed: " + (await uploadRes.text()), { status: 500 });
    }

    return new Response("Uploaded!", { status: 200 });
  },
};

// Helpers
async function hashHex(data: ArrayBuffer | string) {
  const enc = new TextEncoder();
  const buffer = typeof data === "string" ? enc.encode(data) : new Uint8Array(data);
  const hash = await crypto.subtle.digest("SHA-256", buffer);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hmac(key: CryptoKey, msg: string) {
  const enc = new TextEncoder().encode(msg);
  return crypto.subtle.sign("HMAC", key, enc);
}

async function getKey(key: ArrayBuffer) {
  return crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

async function hmacHex(key: ArrayBuffer, msg: string) {
  const cryptoKey = await getKey(key);
  const sig = await hmac(cryptoKey, msg);
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function getSignatureKey(key: string, date: string, region: string, service: string) {
  const enc = new TextEncoder();
  const kDate = await hmac(await getKey(enc.encode("AWS4" + key)), date);
  const kRegion = await hmac(await getKey(kDate), region);
  const kService = await hmac(await getKey(kRegion), service);
  const kSigning = await hmac(await getKey(kService), "aws4_request");
  return kSigning;
}
