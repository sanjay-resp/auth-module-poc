const crypto = require('crypto');
const { subtle } = require("crypto").webcrypto;
const base64url = require("base64url");
(async () => {
const jwt = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjVkMTJhYjc4MmNiNjA5NjI4NWY2OWU0OGFlYTk5MDc5YmI1OWNiODYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIyMjA4NDA5MDA1MDQtZWpqMGs0azFyczVnNTV1a3RnYjdtMTNpMmZybW9zZzAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIyMjA4NDA5MDA1MDQtZWpqMGs0azFyczVnNTV1a3RnYjdtMTNpMmZybW9zZzAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTI1MzY4MTIxNTgwNDU0OTU4NDAiLCJoZCI6Im5naXQuY29tLm5wIiwiZW1haWwiOiJpY2hjaGhhQG5naXQuY29tLm5wIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJpTGI0UGJWYlFNMUx2SWRxdVJlWkRBIiwibm9uY2UiOiJpcmFtIiwibmFtZSI6IkljaGNoaGEgUmFtIEthZmxlIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0pBRmZrbTZ4N3A1eVJXV215Yi15NkZuNHBhTzZHWVhub0FMbzBKLXF6c3V1NnNzdz1zOTYtYyIsImdpdmVuX25hbWUiOiJJY2hjaGhhIFJhbSIsImZhbWlseV9uYW1lIjoiS2FmbGUiLCJpYXQiOjE3NDAxMDk5NzksImV4cCI6MTc0MDExMzU3OX0.uUYt-pcC5KyEpVotPAznKN-1r95rg7OBMdGVXi3AZu30jK1KkkS7GWTbZrg5nchOkNccbcqN8SxT4voe_p_63FqSnlUrsCz2JYifDqcY9-YVRTQ-Tm5w81kHzkCx_oA5AGloh-fcrk4LpVYk1etLUg-_P-yXtuzUG9Mfm8hfr9ozInvbooowV7vfdLcWo0LzDUeNeexFpY7sr3si_BfkldTjCCy7Lf444QAI1Nvs1p-bM8OoP9IsB5GWV7iIFsCX8MO3B_dOQQ6JuxuGiHqM36CEnKLZgGLLuHPu_y23yEe-nLrNMd3ZuBoNArikbrWndCnDE1gCO_rUDk7WqL70Rw';

const jwk = {
  kty: "RSA",
  n: "uac7NRcojCutcceWq1nrpLGJjQ7ywvgWsUcb1DWMKJ3KNNHiRzh9jshoi9tmq1zlarJ_h7GQg8iU1qD7SgpVYJmjlKG1MNVRAtuNrNMC0UAnNfG7mBBNorHFndfp-9cLTiMjXSXRzhNqiMvTVKeolRdMB2lH9RzJnwlpXtvUbD7M1pXOlPlMaOy1zxUnHn0uszU5mPRQk79i03BNrAdhwrAUB-ZuMnqpjaUcb9VU3KIwuZNPtsVenLN12sRYpaZ6WBw8Q9q7fAoaJUovM0Go8deC9pJYyxJuHdVo9HP0osyzg3g_rOYi14wmvMBuiDf3F4pTnudAfFyl3d0Mn_i4ZQ",
  e: "AQAB",
};


const [headerB64, payloadB64, signatureB64] = jwt.split('.');


const message = `${headerB64}.${payloadB64}`;
const signature = base64url.toBuffer(signatureB64);

async function jwkToCryptoKey(jwk) {
  return await subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

console.log("test");
const publicKey = await jwkToCryptoKey(jwk);
const isVerified = await subtle.verify(
  { name: "RSASSA-PKCS1-v1_5" },
  publicKey,
  signature,
  Buffer.from(message) // Pass the raw message
);

console.log("Signature Verified:", isVerified);

})();