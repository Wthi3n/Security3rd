// generate_token.js
// Node.js script: create compact JWS (ES256) from PRIVATE_KEY_PEM env var
import fs from "fs";
import { importPKCS8, CompactSign } from "jose";

async function main() {
  const privPem = process.env.ECDSA_PRIVATE_PEM;
  if (!privPem) {
    console.error("Missing ECDSA_PRIVATE_PEM env var (GitHub Secret).");
    process.exit(1);
  }

  // import private key for ES256
  const key = await importPKCS8(privPem, "ES256");

  const now = Math.floor(Date.now() / 1000);
  // Customize payload claims as you want
  const payload = {
    iss: "github-license-server",
    iat: now,
    exp: now + 3600, // TTL: 1 hour
    bundle_id: "com.your.company.app",
    version: "pro-v1",
    note: "Signed by GH Actions"
  };

  const encoder = new TextEncoder();
  const protectedHeader = { alg: "ES256", typ: "JWT" };

  const jws = await new CompactSign(encoder.encode(JSON.stringify(payload)))
    .setProtectedHeader(protectedHeader)
    .sign(key);

  const out = {
    token: jws,
    payload: payload
  };

  fs.writeFileSync("token.json", JSON.stringify(out, null, 2));
  console.log("Wrote token.json");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
