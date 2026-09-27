import { SignJWT } from "jose";
import type { Env } from "./env";
import { renderLoginPage } from "./render";
import { validateKeyserverHost } from "./keyserver";
import { resolveRequestedFields } from "./scopes";

const FINGERPRINT_RE = /^[0-9A-F]{40}$/;

export async function handleAuthorize(
    req: Request,
    env: Env,
): Promise<Response> {
    const url = new URL(req.url);
    const client_id = url.searchParams.get("client_id");
    const redirect_uri = url.searchParams.get("redirect_uri");
    const state = url.searchParams.get("state") ?? "";
    const nonce = url.searchParams.get("nonce") ?? "";
    const rawFingerprint = url.searchParams.get("login_hint");
    const rawKeyserver = url.searchParams.get("keyserver");
    const requestedFields = resolveRequestedFields(
        url.searchParams.get("scope"),
    );

    if (!client_id || !redirect_uri) {
        return new Response("Missing client_id or redirect_uri", {
            status: 400,
        });
    }

    let keyserver = "";
    if (rawKeyserver) {
        const validated = validateKeyserverHost(rawKeyserver);
        if (!validated)
            return new Response("Invalid keyserver host", { status: 400 });
        keyserver = validated;
    }

    if (!rawFingerprint) {
        return new Response(
            renderLoginPage({
                service: client_id,
                challenge: "",
                fingerprint: "",
                keyserver,
                requestedFields,
            }),
            { headers: { "content-type": "text/html" } },
        );
    }

    const fingerprint = rawFingerprint.trim().toUpperCase();
    if (!FINGERPRINT_RE.test(fingerprint)) {
        return new Response(
            "login_hint must be a 40-character hex key fingerprint",
            { status: 400 },
        );
    }

    const secret = new TextEncoder().encode(env.INTERNAL_HMAC_SECRET);
    const challenge = await new SignJWT({
        client_id,
        redirect_uri,
        state,
        nonce,
        fpr: fingerprint,
        keyserver,
        requestedClaims: requestedFields.map((f) => f.claim),
    })
        .setProtectedHeader({ alg: "HS256" })
        .setIssuedAt()
        .setExpirationTime("90s")
        .sign(secret);

    return new Response(
        renderLoginPage({
            service: client_id,
            challenge,
            fingerprint,
            keyserver,
            requestedFields,
        }),
        { headers: { "content-type": "text/html" } },
    );
}
