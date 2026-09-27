import { jwtVerify, SignJWT, importJWK } from "jose";
import type { Env } from "./env";

export async function handleToken(req: Request, env: Env) {
    const form = await req.formData();
    if (form.get("grant_type") !== "authorization_code") {
        return Response.json(
            { error: "unsupported_grant_type" },
            { status: 400 },
        );
    }
    const code = form.get("code") as string;
    const client_id = form.get("client_id") as string;
    const redirect_uri = form.get("redirect_uri") as string;

    const secret = new TextEncoder().encode(env.INTERNAL_HMAC_SECRET);
    let payload: Record<string, unknown>;
    try {
        ({ payload } = await jwtVerify(code, secret));
    } catch {
        return Response.json({ error: "invalid_grant" }, { status: 400 });
    }

    const {
        client_id: expected_client_id,
        redirect_uri: expected_redirect_uri,
        sub,
        nonce,
        claims,
    } = payload as {
        client_id?: string;
        redirect_uri?: string;
        sub?: string;
        nonce?: string;
        claims?: Record<string, string>;
    };
    if (!expected_client_id || !expected_redirect_uri || !sub) {
        return Response.json({ error: "invalid_grant" }, { status: 400 });
    }
    if (
        expected_client_id !== client_id ||
        expected_redirect_uri !== redirect_uri
    ) {
        return Response.json({ error: "invalid_grant" }, { status: 400 });
    }

    const idTokenClaims: Record<string, unknown> = { nonce, ...claims };
    if (claims?.email) idTokenClaims.email_verified = false;

    const jwk = JSON.parse(env.OP_SIGNING_JWK);
    const privateKey = await importJWK(jwk, "EdDSA");
    const id_token = await new SignJWT(idTokenClaims)
        .setProtectedHeader({ alg: "EdDSA", kid: jwk.kid })
        .setIssuer(env.ISSUER)
        .setAudience(client_id)
        .setSubject(sub)
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey);

    return Response.json({ token_type: "Bearer", id_token, expires_in: 300 });
}
