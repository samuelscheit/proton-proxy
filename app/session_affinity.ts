import { createHash } from "crypto";

/** The only proxy-auth username that carries rotating-listener affinity. */
export const PROTON_SESSION_USERNAME = "proton-session";

const BASIC_HEADER = /^\s*proxy-authorization\s*:\s*basic\s+([^\s]+)\s*$/im;
const BASE64_TOKEN = /^[A-Za-z0-9+/]+={0,2}$/;
const SESSION_TOKEN = /^[a-f0-9]{64}$/i;

/**
 * Extract the opaque session token from an HTTP CONNECT header block.
 *
 * The proxy remains unauthenticated for normal callers. Only a Basic auth
 * value with the reserved `proton-session` username is interpreted; all other
 * credentials are ignored and never logged. Tokens are intentionally strict so
 * malformed or attacker-controlled headers cannot affect tunnel selection.
 */
export function parseProtonSessionToken(headerText: string): string | undefined {
	const match = BASIC_HEADER.exec(headerText);
	if (!match) return undefined;
	const encoded = match[1];
	if (encoded.length > 512 || encoded.length % 4 !== 0 || !BASE64_TOKEN.test(encoded)) return undefined;
	let decoded: string;
	try {
		decoded = Buffer.from(encoded, "base64").toString("utf8");
	} catch {
		return undefined;
	}
	const separator = decoded.indexOf(":");
	if (separator <= 0 || decoded.indexOf("\0") >= 0) return undefined;
	const username = decoded.slice(0, separator);
	const token = decoded.slice(separator + 1).trim().toLowerCase();
	if (username !== PROTON_SESSION_USERNAME || !SESSION_TOKEN.test(token)) return undefined;
	return token;
}

/**
 * Choose an available candidate using rendezvous hashing.
 *
 * `candidateIds` must be stable identifiers (the service uses interface names)
 * and `sessionToken` is already opaque. Returning the index rather than the
 * candidate keeps this helper independent of the tunnel state type.
 */
export function rendezvousIndex(
	sessionToken: string,
	candidateIds: readonly string[],
): number | undefined {
	if (!SESSION_TOKEN.test(sessionToken) || candidateIds.length === 0) return undefined;
	let selectedIndex: number | undefined;
	let selectedScore = "";
	for (let index = 0; index < candidateIds.length; index += 1) {
		const candidateId = candidateIds[index];
		const score = createHash("sha256")
			.update("proton-session-affinity-v1\0")
			.update(sessionToken)
			.update("\0")
			.update(candidateId)
			.digest("hex");
		if (selectedIndex === undefined || score > selectedScore) {
			selectedIndex = index;
			selectedScore = score;
		}
	}
	return selectedIndex;
}
