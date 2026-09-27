import { jwtVerify, SignJWT } from "jose";
import * as openpgp from "openpgp";
import type { Env } from "./env";
import { buildKeyLookupUrl, resolveAndPinKeyserver } from "./keyserver";

export async function handleVerify(req: Request, env: Env) {
    const form = await req.formData();
    const challenge = form.get("challenge") as string | null;
    const signed = form.get("signature") as string | null;
    if (!challenge || !signed) {
        return new Response("Missing challenge or signature", { status: 400 });
    }

    const secret = new TextEncoder().encode(env.INTERNAL_HMAC_SECRET);
    let payload: Record<string, unknown>;
    try {
        ({ payload } = await jwtVerify(challenge, secret));
    } catch {
        return new Response("Challenge expired or invalid", { status: 400 });
    }

    const {
        client_id,
        redirect_uri,
        state,
        nonce,
        fpr,
        keyserver,
        requestedClaims,
    } = payload as {
        client_id?: string;
        redirect_uri?: string;
        state?: string;
        nonce?: string;
        fpr?: string;
        keyserver?: string;
        requestedClaims?: string[];
    };
    if (!client_id || !redirect_uri || !fpr) {
        return new Response("Malformed challenge", { status: 400 });
    }

    let pinned;
    try {
        pinned = await resolveAndPinKeyserver(keyserver || "keys.openpgp.org");
    } catch {
        return new Response("Could not safely resolve keyserver", {
            status: 400,
        });
    }

    const lookupUrl = buildKeyLookupUrl(fpr, pinned.host);
    const keyResp = await fetch(lookupUrl, {
        cf: { resolveOverride: pinned.pinnedIp },
    });
    if (!keyResp.ok)
        return new Response("Could not resolve key", { status: 400 });
    const publicKey = await openpgp.readKey({
        armoredKey: await keyResp.text(),
    });

    const message = await openpgp.readCleartextMessage({
        cleartextMessage: signed,
    });
    if (message.getText().trim() !== challenge.trim()) {
        return new Response(
            "Signed content doesn't match the issued challenge",
            { status: 400 },
        );
    }

    const result = await openpgp.verify({
        message,
        verificationKeys: publicKey,
    });
    try {
        const signature = result.signatures[0];
        if (!signature) throw new Error("Missing signature");
        await signature.verified;
    } catch {
        return new Response("Signature verification failed", { status: 400 });
    }

    const expiry = await publicKey.getExpirationTime();
    if (expiry instanceof Date && expiry < new Date()) {
        return new Response("Key expired", { status: 400 });
    }

    const claims: Record<string, string> = {};
    for (const claim of requestedClaims ?? []) {
        const value = form.get(`claim_${claim}`);
        if (typeof value === "string" && value.trim()) {
            claims[claim] = value.trim();
        }
    }

    const code = await new SignJWT({
        client_id,
        redirect_uri,
        nonce,
        sub: fpr,
        claims,
    })
        .setProtectedHeader({ alg: "HS256" })
        .setIssuedAt()
        .setExpirationTime("60s")
        .sign(secret);

    const redirect = new URL(redirect_uri);
    redirect.searchParams.set("code", code);
    if (state) redirect.searchParams.set("state", state);
    return Response.redirect(redirect.toString(), 302);
}
