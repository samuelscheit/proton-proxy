import assert from "assert/strict";
import test from "node:test";

import {
	PROTON_SESSION_USERNAME,
	parseProtonSessionToken,
	rendezvousIndex,
	stripProxyAuthorizationHeaders,
} from "./session_affinity.ts";

function basic(value: string): string {
	return Buffer.from(value, "utf8").toString("base64");
}

test("parses only the reserved opaque Proton session credential", () => {
	const token = "a".repeat(64);
	const headers = [
		"CONNECT chatgpt.com:443 HTTP/1.1",
		`Proxy-Authorization: Basic ${basic(`${PROTON_SESSION_USERNAME}:${token}`)}`,
		"",
	].join("\r\n");
	assert.equal(parseProtonSessionToken(headers), token);
	assert.equal(
		parseProtonSessionToken(
			headers.replace(
				basic(`${PROTON_SESSION_USERNAME}:${token}`),
				basic(`other-user:${token}`),
			),
		),
		undefined,
	);
	assert.equal(
		parseProtonSessionToken(
			headers.replace(
				basic(`${PROTON_SESSION_USERNAME}:${token}`),
				basic(`${PROTON_SESSION_USERNAME}:not-a-valid-token`),
			),
		),
		undefined,
	);
});

test("removes proxy credentials before an absolute HTTP request is forwarded", () => {
	const request = [
		"GET http://example.test/ HTTP/1.1",
		"Host: example.test",
		`Proxy-Authorization: Basic ${basic(`${PROTON_SESSION_USERNAME}:${"a".repeat(64)}`)}`,
		"Proxy-Authorization: Basic should-not-reach-the-origin",
		"Accept: */*",
	].join("\r\n");
	const forwarded = stripProxyAuthorizationHeaders(request);
	assert.match(forwarded, /^GET http:\/\/example\.test\/ HTTP\/1\.1/m);
	assert.match(forwarded, /Host: example\.test/);
	assert.match(forwarded, /Accept: \*\/\*/);
	assert.doesNotMatch(forwarded, /proxy-authorization/i);
});

test("session selection is stable and remaps only when its selected candidate disappears", () => {
	const token = "b".repeat(64);
	const candidates = ["wg0", "wg1", "wg2", "wg3"];
	const first = rendezvousIndex(token, candidates);
	assert.notEqual(first, undefined);
	assert.equal(rendezvousIndex(token, candidates), first);
	assert.equal(rendezvousIndex(token, candidates.slice()), first);

	const remaining = candidates.filter((_, index) => index !== first);
	const remapped = rendezvousIndex(token, remaining);
	assert.notEqual(remapped, undefined);
	assert.notEqual(remaining[remapped!], candidates[first!]);
});

test("rendezvous selection distributes independent sessions", () => {
	const candidates = Array.from({ length: 20 }, (_, index) => `wg${index}`);
	const selected = new Set(
		Array.from({ length: 500 }, (_, index) => {
			const token = index.toString(16).padStart(64, "0");
			return candidates[rendezvousIndex(token, candidates)!];
		}),
	);
	assert.ok(selected.size > 1);
	assert.ok(selected.size <= candidates.length);
});
