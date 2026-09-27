export interface RequestedField {
    claim: string;
    label: string;
    type: "email" | "text";
}

// Add to this map to support more optional scopes later - each scope key
// can expand to multiple claim fields.
const SCOPE_FIELDS: Record<string, RequestedField[]> = {
    email: [{ claim: "email", label: "Email address", type: "email" }],
    profile: [{ claim: "name", label: "Display name", type: "text" }],
};

export function resolveRequestedFields(
    scopeParam: string | null,
): RequestedField[] {
    const scopes = (scopeParam ?? "").split(/\s+/).filter(Boolean);
    const fields: RequestedField[] = [];
    for (const scope of scopes) {
        const mapped = SCOPE_FIELDS[scope];
        if (mapped) fields.push(...mapped);
    }
    return fields;
}
