function ipv4ToInt(ip: string): number | null {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
    if (!m) return null;
    const parts = [m[1]!, m[2]!, m[3]!, m[4]!].map(Number);
    if (parts.some((p) => p > 255)) return null;
    return (
        ((parts[0]! << 24) |
            (parts[1]! << 16) |
            (parts[2]! << 8) |
            parts[3]!) >>>
        0
    );
}

function parseCidr4(cidr: string): { base: number; mask: number } {
    const [addr, bitsStr] = cidr.split("/");
    const bits = Number(bitsStr ?? "0");
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return { base: ipv4ToInt(addr ?? "")! & mask, mask };
}

const BLOCKED_IPV4_CIDRS = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10", // CGNAT
    "127.0.0.0/8", // localhost
    "169.254.0.0/16", // link-local — covers AWS/GCP/Azure IMDS at 169.254.169.254
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24", // TEST-NET-1
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24", // TEST-NET-2
    "203.0.113.0/24", // TEST-NET-3
    "224.0.0.0/4", // multicast
    "240.0.0.0/4", // reserved
];
const BLOCKED_RANGES_V4 = BLOCKED_IPV4_CIDRS.map(parseCidr4);

function isBlockedIpv4(ip: string): boolean {
    const int = ipv4ToInt(ip);
    if (int === null) return false;
    return BLOCKED_RANGES_V4.some(({ base, mask }) => (int & mask) === base);
}

function ipv6ToBigInt(ip: string): bigint | null {
    let working = ip;

    const v4Tail = /^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(working);
    if (v4Tail) {
        const v4Int = ipv4ToInt(v4Tail[2]!);
        if (v4Int === null) return null;
        const hi = ((v4Int >>> 16) & 0xffff).toString(16);
        const lo = (v4Int & 0xffff).toString(16);
        working = `${v4Tail[1]!}${hi}:${lo}`;
    }

    if (!/^[0-9a-fA-F:]+$/.test(working)) return null;
    const sides = working.split("::");
    if (sides.length > 2) return null;

    const leftRaw = sides[0] ?? "";
    const rightRaw = sides.length === 2 ? (sides[1] ?? "") : "";

    const left = leftRaw === "" ? [] : leftRaw.split(":");
    const right =
        sides.length === 2 && rightRaw !== "" ? rightRaw.split(":") : [];
    const missing = 8 - left.length - right.length;
    if (sides.length === 1 && missing !== 0) return null;
    if (sides.length === 2 && missing < 0) return null;

    const groups = [
        ...left,
        ...Array(sides.length === 2 ? missing : 0).fill("0"),
        ...right,
    ];
    if (groups.length !== 8) return null;

    let value = 0n;
    for (const g of groups) {
        if (g.length === 0 || g.length > 4) return null;
        value = (value << 16n) | BigInt(parseInt(g, 16));
    }
    return value;
}

function parseCidr6(cidr: string): { base: bigint; mask: bigint } {
    const [addr, bitsStr] = cidr.split("/");
    const bits = Number(bitsStr ?? "0");
    const full = (1n << 128n) - 1n;
    const mask = bits === 0 ? 0n : (full << BigInt(128 - bits)) & full;
    const addrInt = ipv6ToBigInt(addr ?? "");
    if (addrInt === null) throw new Error(`invalid IPv6 CIDR literal: ${cidr}`);
    return { base: addrInt & mask, mask };
}

const BLOCKED_IPV6_CIDRS = [
    "::1/128", // Loopback
    "::/128", // Unspecified
    "::ffff:0:0/96", // IPv4-mapped range — belt-and-suspenders, the unwrapped v4 check already catches these
    "fe80::/10", // Link-local — where IPv6 metadata-equivalents live
    "fc00::/7", // Unique local, IPv6's RFC1918 equivalent
];
const BLOCKED_RANGES_V6 = BLOCKED_IPV6_CIDRS.map(parseCidr6);

function isBlockedIpv6(ip: string): boolean {
    const int = ipv6ToBigInt(ip);
    if (int === null) return false;
    return BLOCKED_RANGES_V6.some(({ base, mask }) => (int & mask) === base);
}

function isBlockedIp(ip: string): boolean {
    return isBlockedIpv4(ip) || isBlockedIpv6(ip);
}

const HOSTNAME_RE =
    /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;

const BLOCKED_HOSTNAMES = new Set([
    "localhost",
    "metadata.google.internal",
    "metadata.amazonaws.com",
]);

export function validateKeyserverHost(raw: string): string | null {
    let url: URL;
    try {
        url = new URL(`https://${raw.trim()}`);
    } catch {
        return null;
    }
    if (
        url.username ||
        url.password ||
        url.pathname !== "/" ||
        url.search ||
        url.hash
    ) {
        return null;
    }

    const host = url.hostname.toLowerCase();
    if (host.startsWith("[")) return null;

    if (BLOCKED_HOSTNAMES.has(host.replace(/\.$/, ""))) return null;

    if (ipv4ToInt(host) !== null) {
        return isBlockedIpv4(host) ? null : host;
    }
    return HOSTNAME_RE.test(host) ? host : null;
}

export function buildKeyLookupUrl(fingerprint: string, host: string): string {
    return `https://${host}/vks/v1/by-fingerprint/${fingerprint}`;
}

interface DohAnswer {
    data: string;
}
interface DohResponse {
    Answer?: DohAnswer[];
}

async function dohLookup(
    hostname: string,
    type: "A" | "AAAA",
): Promise<string[]> {
    const resp = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`,
        { headers: { accept: "application/dns-json" } },
    );
    if (!resp.ok) return [];
    const body = (await resp.json()) as DohResponse;
    return (body.Answer ?? []).map((a) => a.data);
}

export interface PinnedKeyserver {
    host: string;
    pinnedIp: string;
}

export async function resolveAndPinKeyserver(
    host: string,
): Promise<PinnedKeyserver> {
    if (ipv4ToInt(host) !== null) {
        if (isBlockedIp(host)) throw new Error("keyserver address is blocked");
        return { host, pinnedIp: host };
    }

    const [v4, v6] = await Promise.all([
        dohLookup(host, "A"),
        dohLookup(host, "AAAA"),
    ]);
    const all = [...v4, ...v6];
    if (all.length === 0) throw new Error("keyserver did not resolve");
    if (all.some((ip) => isBlockedIp(ip))) {
        throw new Error("keyserver resolved to a blocked address");
    }

    return { host, pinnedIp: all[0]! };
}
