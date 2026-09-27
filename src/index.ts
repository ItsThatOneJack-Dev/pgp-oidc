import { discoveryDocument, jwks } from "./wellknown";
import { handleAuthorize } from "./authorize";
import { handleVerify } from "./verify";
import { handleToken } from "./token";
import { renderLandingPage, renderAddPage, renderFAQ } from "./render";
import type { Env } from "./env";

export default {
    async fetch(req: Request, env: Env): Promise<Response> {
        const url = new URL(req.url);

        if (url.pathname === "/" && req.method === "GET") {
            return new Response(renderLandingPage(), {
                headers: { "content-type": "text/html" },
            });
        }
        if (url.pathname === "/add" && req.method === "GET") {
            return new Response(renderAddPage(), {
                headers: { "content-type": "text/html" },
            });
        }
        if (url.pathname === "/faq" && req.method === "GET") {
            return new Response(renderFAQ(), {
                headers: { "content-type": "text/html" },
            });
        }
        if (url.pathname === "/.well-known/openid-configuration")
            return Response.json(discoveryDocument(env.ISSUER));
        if (url.pathname === "/.well-known/jwks.json")
            return Response.json(jwks(env));
        if (url.pathname === "/authorize") return handleAuthorize(req, env);
        if (url.pathname === "/verify" && req.method === "POST")
            return handleVerify(req, env);
        if (url.pathname === "/token" && req.method === "POST")
            return handleToken(req, env);
        if (url.pathname.startsWith("/favicon")) {
            let base = new URL(req.url).hostname.split(".").slice(1).join(".");
            return Response.redirect(`${base}${url.pathname}`, 308); // Proxy the thing through to the base, so we don't need to build this with a favicon in.
        }

        const fpr = url.pathname.match(/^\/([0-9A-Fa-f]{40})$/);
        if (fpr) {
            const dest = new URL("/authorize", url);
            dest.search = url.search;
            dest.searchParams.set("login_hint", fpr[1]!.toUpperCase());
            return Response.redirect(dest.toString(), 302);
        }

        return new Response("Not found", { status: 404 });
    },
};
