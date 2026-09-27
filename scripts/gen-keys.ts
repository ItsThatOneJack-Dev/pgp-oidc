import { generateKeyPair, exportJWK } from "jose";
import { randomBytes } from "node:crypto";

const { privateKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
});
const jwk = await exportJWK(privateKey);
jwk.kid = crypto.randomUUID();
jwk.alg = "EdDSA";

console.log("OP_SIGNING_JWK:", JSON.stringify(jwk));
console.log("INTERNAL_HMAC_SECRET:", randomBytes(32).toString("base64url"));
