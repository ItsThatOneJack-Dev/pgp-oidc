import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { decodeJwt, createRemoteJWKSet, jwtVerify } from "jose";

const execAsync = promisify(exec);

const CLIENT_ID = "oidc-test";
const CALLBACK_HOST = "127.0.0.1";

interface DiscoveryDocument {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    userinfo_endpoint?: string;
    jwks_uri?: string;

    scopes_supported?: string[];
    response_types_supported?: string[];
    response_modes_supported?: string[];
    grant_types_supported?: string[];
    code_challenge_methods_supported?: string[];
}

function randomString(bytes = 32): string {
    const data = new Uint8Array(bytes);
    crypto.getRandomValues(data);

    return Buffer.from(data).toString("base64url");
}

function sha256Base64Url(value: string): string {
    return createHash("sha256").update(value).digest("base64url");
}

function normaliseIssuer(input: string): {
    issuer: string;
    hint?: string;
} {
    input = input.trim();

    if (!/^https?:\/\//i.test(input)) {
        input = `https://${input}`;
    }

    const url = new URL(input);

    // The hostname/path before the final path is the issuer.
    //
    // Example:
    //   oidc.itoj.dev
    //       -> issuer https://oidc.itoj.dev/
    //
    //   oidc.itoj.dev/jack
    //       -> issuer https://oidc.itoj.dev/
    //          login_hint = jack
    //
    //   oidc.itoj.dev/foo/bar
    //       -> issuer https://oidc.itoj.dev/
    //          login_hint = foo/bar

    const hint = url.pathname.replace(/^\/+/, "").replace(/\/+$/, "");

    url.pathname = "/";
    url.search = "";
    url.hash = "";

    return {
        issuer: url.toString(),
        hint: hint || undefined,
    };
}

async function discover(issuer: string): Promise<DiscoveryDocument> {
    const discoveryUrl = new URL(".well-known/openid-configuration", issuer);

    console.log(`\nDiscovery URL: ${discoveryUrl}`);

    const response = await fetch(discoveryUrl);

    if (!response.ok) {
        throw new Error(
            `Discovery failed: HTTP ${response.status} ${response.statusText}`,
        );
    }

    const document = (await response.json()) as DiscoveryDocument;

    if (!document.issuer) {
        throw new Error("Discovery document has no issuer");
    }

    if (!document.authorization_endpoint) {
        throw new Error("Discovery document has no authorization_endpoint");
    }

    if (!document.token_endpoint) {
        throw new Error("Discovery document has no token_endpoint");
    }

    return document;
}

function printDiscovery(document: DiscoveryDocument) {
    console.log("\n=== Discovery ===");

    console.log(`issuer:              ${document.issuer}`);
    console.log(`authorization:       ${document.authorization_endpoint}`);
    console.log(`token:               ${document.token_endpoint}`);
    console.log(
        `userinfo:            ${document.userinfo_endpoint ?? "(none)"}`,
    );
    console.log(`jwks:                ${document.jwks_uri ?? "(none)"}`);

    console.log(
        `response types:      ${
            document.response_types_supported?.join(", ") ?? "(not advertised)"
        }`,
    );

    console.log(
        `grant types:         ${
            document.grant_types_supported?.join(", ") ?? "(not advertised)"
        }`,
    );

    console.log(
        `PKCE methods:        ${
            document.code_challenge_methods_supported?.join(", ") ??
            "(not advertised)"
        }`,
    );
}

async function selectScopes(
    rl: ReturnType<typeof createInterface>,
    document: DiscoveryDocument,
): Promise<string[]> {
    const advertised = document.scopes_supported ?? [];

    console.log("\n=== Scopes ===");

    if (advertised.length === 0) {
        console.log("Provider did not advertise scopes_supported.");

        const answer = await rl.question(
            "Enter scopes separated by spaces [openid]: ",
        );

        const scopes = answer.trim().split(/\s+/).filter(Boolean);

        return ["openid", ...scopes.filter((scope) => scope !== "openid")];
    }

    console.log("Select scopes by number. " + "openid is mandatory for OIDC.");

    for (let i = 0; i < advertised.length; i++) {
        const scope = advertised[i];

        console.log(
            `  ${i + 1}. ${scope}` + (scope === "openid" ? " [required]" : ""),
        );
    }

    const defaultSelection = advertised
        .map((scope, index) => (scope === "openid" ? String(index + 1) : ""))
        .filter(Boolean)
        .join(",");

    const answer = await rl.question(
        `\nScopes to request [${defaultSelection}]: `,
    );

    const selection = answer.trim() === "" ? defaultSelection : answer;

    const scopes = new Set<string>();

    for (const part of selection.split(",")) {
        const number = Number(part.trim());

        if (
            Number.isInteger(number) &&
            number >= 1 &&
            number <= advertised.length
        ) {
            const scope = advertised[number - 1];

            if (scope !== undefined) {
                scopes.add(scope);
            }
        }
    }

    // OIDC requires openid.
    scopes.add("openid");

    return [...scopes];
}

async function openBrowser(url: string) {
    console.log("\nOpening browser...");

    if (process.platform === "win32") {
        await execAsync(`start "" "${url.replaceAll('"', '\\"')}"`);
    } else if (process.platform === "darwin") {
        await execAsync(`open "${url.replaceAll('"', '\\"')}"`);
    } else {
        await execAsync(`xdg-open "${url.replaceAll('"', '\\"')}"`);
    }
}

function waitForCallback(
    server: ReturnType<typeof createServer>,
): Promise<URL> {
    return new Promise((resolve, reject) => {
        server.on("request", (request, response) => {
            if (!request.url) {
                response.writeHead(400);
                response.end("Bad request");
                return;
            }

            const url = new URL(request.url, `http://${CALLBACK_HOST}`);

            if (url.pathname !== "/callback") {
                response.writeHead(404);
                response.end("Not found");
                return;
            }

            if (url.searchParams.has("error")) {
                response.writeHead(400);
                response.end(
                    "OIDC authentication failed. You can close this tab.",
                );

                resolve(url);
                return;
            }

            response.writeHead(200, {
                "Content-Type": "text/html; charset=utf-8",
            });

            response.end(`
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>OIDC test complete</title>
</head>
<body>
    <h1>OIDC authentication complete</h1>
    <p>You can close this tab and return to the terminal.</p>
</body>
</html>
`);

            resolve(url);
        });

        server.on("error", reject);
    });
}

async function main() {
    const rl = createInterface({
        input,
        output,
    });

    try {
        console.log("=== OIDC RP Test Client ===\n");

        const inputUrl = await rl.question("OIDC provider URL: ");

        const { issuer, hint } = normaliseIssuer(inputUrl);

        console.log(`\nIssuer: ${issuer}`);

        if (hint) {
            console.log(`Login hint: ${hint}`);
        }

        const discovery = await discover(issuer);

        printDiscovery(discovery);

        const scopes = await selectScopes(rl, discovery);

        console.log(`\nRequested scopes: ${scopes.join(" ")}`);

        /*
         * Create an ephemeral loopback listener.
         *
         * Using port 0 lets the OS select an available port.
         */
        const server = createServer();

        await new Promise<void>((resolve, reject) => {
            server.listen(0, CALLBACK_HOST, () => resolve());

            server.once("error", reject);
        });

        const address = server.address();

        if (!address || typeof address === "string") {
            throw new Error("Could not determine callback port");
        }

        const redirectUri = `http://${CALLBACK_HOST}:${address.port}/callback`;

        console.log(`Callback: ${redirectUri}`);

        /*
         * OAuth/OIDC state.
         */
        const state = randomString(32);

        /*
         * OIDC nonce.
         *
         * The provider should put this into the ID token.
         */
        const nonce = randomString(32);

        /*
         * PKCE.
         */
        const codeVerifier = randomString(48);

        const codeChallenge = sha256Base64Url(codeVerifier);

        const authorizationUrl = new URL(discovery.authorization_endpoint);

        authorizationUrl.searchParams.set("response_type", "code");

        authorizationUrl.searchParams.set("client_id", CLIENT_ID);

        authorizationUrl.searchParams.set("redirect_uri", redirectUri);

        authorizationUrl.searchParams.set("scope", scopes.join(" "));

        authorizationUrl.searchParams.set("state", state);

        authorizationUrl.searchParams.set("nonce", nonce);

        authorizationUrl.searchParams.set("code_challenge", codeChallenge);

        authorizationUrl.searchParams.set("code_challenge_method", "S256");

        /*
         * This is deliberately a normal login_hint.
         *
         * So:
         *
         *   oidc.itoj.dev
         *
         * becomes:
         *
         *   no login_hint
         *
         * while:
         *
         *   oidc.itoj.dev/jack
         *
         * becomes:
         *
         *   login_hint=jack
         *
         * Your provider can interpret that however
         * makes sense for your system.
         */
        if (hint) {
            authorizationUrl.searchParams.set("login_hint", hint);
        }

        console.log("\n=== Authorization Request ===\n");

        console.log(authorizationUrl.toString());

        console.log("\nWaiting for callback...");

        await openBrowser(authorizationUrl.toString());

        const callback = await waitForCallback(server);

        server.close();

        /*
         * Check OAuth error response.
         */
        const error = callback.searchParams.get("error");

        if (error) {
            console.error("\n=== Provider Error ===");

            console.error("error:", error);

            console.error(
                "error_description:",
                callback.searchParams.get("error_description"),
            );

            console.error("error_uri:", callback.searchParams.get("error_uri"));

            return;
        }

        /*
         * Verify state.
         */
        const returnedState = callback.searchParams.get("state");

        if (returnedState !== state) {
            throw new Error("STATE MISMATCH — refusing to continue");
        }

        const code = callback.searchParams.get("code");

        if (!code) {
            throw new Error("No authorization code returned");
        }

        console.log("\nAuthorization code received.");

        /*
         * Exchange code for tokens.
         *
         * This is a public client, so there is intentionally
         * no client_secret here.
         */
        const tokenBody = new URLSearchParams();

        tokenBody.set("grant_type", "authorization_code");

        tokenBody.set("code", code);

        tokenBody.set("redirect_uri", redirectUri);

        tokenBody.set("client_id", CLIENT_ID);

        tokenBody.set("code_verifier", codeVerifier);

        const tokenResponse = await fetch(discovery.token_endpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                Accept: "application/json",
            },
            body: tokenBody,
        });

        const tokenText = await tokenResponse.text();

        let tokenJson: any;

        try {
            tokenJson = JSON.parse(tokenText);
        } catch {
            throw new Error(`Token endpoint returned non-JSON:\n${tokenText}`);
        }

        console.log("\n=== Token Response ===");

        console.dir(tokenJson, {
            depth: null,
            colors: true,
        });

        if (!tokenResponse.ok) {
            throw new Error(
                `Token endpoint returned HTTP ${tokenResponse.status}`,
            );
        }

        /*
         * Decode ID token.
         *
         * We print the decoded claims regardless of
         * whether cryptographic validation succeeds,
         * which is useful when testing a new provider.
         */
        const idToken = tokenJson.id_token as string | undefined;

        if (!idToken) {
            console.log("\nNo ID token was returned.");
        } else {
            console.log("\n=== Decoded ID Token ===");

            const decoded = decodeJwt(idToken);

            console.dir(decoded, {
                depth: null,
                colors: true,
            });

            /*
             * Basic nonce check.
             */
            if (decoded.nonce !== nonce) {
                console.error("\n❌ NONCE MISMATCH");
            } else {
                console.log("\n✓ nonce matches");
            }

            /*
             * Cryptographic signature + issuer + audience
             * validation.
             */
            if (discovery.jwks_uri) {
                try {
                    const jwks = createRemoteJWKSet(
                        new URL(discovery.jwks_uri),
                    );

                    const verified = await jwtVerify(idToken, jwks, {
                        issuer: discovery.issuer,
                        audience: CLIENT_ID,
                    });

                    console.log("✓ ID token signature valid");

                    console.log("✓ issuer valid");

                    console.log("✓ audience valid");

                    console.log("\n=== Verified Claims ===");

                    console.dir(verified.payload, {
                        depth: null,
                        colors: true,
                    });
                } catch (error) {
                    console.error("\n❌ ID token validation failed:");

                    console.error(error);
                }
            } else {
                console.log(
                    "\nProvider did not advertise jwks_uri; " +
                        "signature validation skipped.",
                );
            }
        }

        /*
         * UserInfo endpoint.
         */
        if (discovery.userinfo_endpoint && tokenJson.access_token) {
            console.log("\n=== UserInfo ===");

            const userinfo = await fetch(discovery.userinfo_endpoint, {
                headers: {
                    Authorization: `Bearer ${tokenJson.access_token}`,
                    Accept: "application/json",
                },
            });

            const userinfoText = await userinfo.text();

            try {
                console.dir(JSON.parse(userinfoText), {
                    depth: null,
                    colors: true,
                });
            } catch {
                console.log(userinfoText);
            }
        }

        console.log("\n=== Test complete ===");
    } finally {
        rl.close();
    }
}

main().catch((error) => {
    console.error("\n❌ Test failed:\n", error);

    process.exitCode = 1;
});
