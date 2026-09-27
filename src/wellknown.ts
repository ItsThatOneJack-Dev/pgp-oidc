import type { Env } from "./env";

export function discoveryDocument(issuer: string) {
    return {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["EdDSA"],
        scopes_supported: ["openid", "email", "profile"],
        claims_supported: ["sub", "email", "email_verified", "name"],
        token_endpoint_auth_methods_supported: ["none"],
    };
}

export function jwks(env: Env) {
    const { d, ...pub } = JSON.parse(env.OP_SIGNING_JWK);
    return { keys: [{ ...pub, use: "sig" }] };
}
