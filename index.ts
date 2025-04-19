// index.ts

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (request.method !== "POST") {
      return new Response("Only POST allowed", { status: 405 });
    }

    const { filename, contentType, fileBase64 } = await request.json();
    const body = Uint8Array.from(atob(fileBase64), c => c.charCodeAt(0));

    const url = `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com/${env.R2_BUCKET}/${filename}`;
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '') + 'Z';
    const dateStamp = amzDate.substring(0, 8);

    const region = "auto"; // works for APAC
    const service = "s3";
    const algorithm = "AWS4-HMAC-SHA256";
    const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;

    const host = `${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;

    const headers = {
      "host": host,
      "x-amz-date": amzDate,
      "x-amz-content-sha256": await hashHex(body),
    };

    const canonicalHeaders = Object.entries(headers)
      .map(([k, v]) => `${k}:${v}\n`).join('');
    const signedHeaders = Object.keys(headers).sort().join(';');

    const canonicalRequest = [
      "PUT",
      `/${env.R2_BUCKET}/${filename}`,
      "",
      canonicalHeaders,
      signedHeaders,
      headers["x-amz-content-sha256"]
    ].join('\n');

    const stringToSign = [
      algorithm,
      amzDate,
      credentialScope,
      await hashHex(canonicalRequest)
    ].join('\n');

    const signingKey = await getSignatureKey(env.R2_SECRET_KEY, dateStamp, region, service);
    const signature = await hmacHex(signingKey, stringToSign);

    const authorizationHeader = `${algorithm} Credential=${env.R2_ACCESS_KEY}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const res = await fetch(url, {
      method: "PUT",
      headers: {
        ...headers,
        "Authorization": authorizationHeader,
        "Content-Type": contentType
      },
      body
    });

    if (!res.ok) {
      const err = await res.text();
      return new Response(`Upload failed:\n${err}`, { status: 500 });
    }

    return new Response(JSON.stringify({ url }), {
      headers: { "Content-Type": "application/json" }
    });
  }
};

async function hmac(key, msg) {
  const enc = new TextEncoder();
  return await crypto.subtle.sign("HMAC", await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]), enc.encode(msg));
}
async function hmacHex(key, msg) {
  const sig = await hmac(key, msg);
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function hashHex(msg) {
  const digest = await crypto.subtle.digest("SHA-256", msg);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function getSignatureKey(key, dateStamp, regionName, serviceName) {
  const kDate = await hmac(new TextEncoder().encode("AWS4" + key), dateStamp);
  const kRegion = await hmac(kDate, regionName);
  const kService = await hmac(kRegion, serviceName);
  const kSigning = await hmac(kService, "aws4_request");
  return kSigning;
}
