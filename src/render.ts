import LOGIN_HTML from "./login.html";
import LANDING_HTML from "./landing.html";
import ADD_HTML from "./add.html";
import FAQ_HTML from "./faq.html";

function escapeHtml(input: string): string {
    return input
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function escapeJsString(input: string): string {
    return input
        .replace(/\\/g, "\\\\")
        .replace(/"/g, '\\"')
        .replace(/</g, "\\u003C")
        .replace(/\r?\n/g, "\\n");
}

export interface RequestedField {
    claim: string;
    label: string;
    type: "email" | "text";
}

export interface LoginPageVars {
    service: string;
    challenge: string;
    fingerprint: string;
    keyserver: string;
    requestedFields: RequestedField[];
}

export function renderLoginPage(vars: LoginPageVars): string {
    const fieldsJson = JSON.stringify(vars.requestedFields).replace(
        /</g,
        "\\u003C",
    );
    return LOGIN_HTML.replaceAll("{SERVICE}", escapeHtml(vars.service))
        .replaceAll("{CHALLENGE}", escapeJsString(vars.challenge))
        .replaceAll("{FINGERPRINT}", vars.fingerprint)
        .replaceAll("{KEYSERVER}", escapeJsString(vars.keyserver))
        .replaceAll("/*{REQUESTED_FIELDS_JSON}*/ undefined", fieldsJson); // Workaround for formatting breaking the placeholder.
}

export function renderAddPage(): string {
    return ADD_HTML;
}

export function renderLandingPage(): string {
    return LANDING_HTML;
}

export function renderFAQ(): string {
    return FAQ_HTML;
}
