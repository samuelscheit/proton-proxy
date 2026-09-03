import assert from "assert/strict";
import { mkdtemp, rm, writeFile } from "fs/promises";
import os from "os";
import path from "path";
import test from "node:test";

import { listTunnelProfiles, stripWireGuardConfig } from "./tunnel_profiles.ts";

const wireGuardProfile = `# generated test profile
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.2.0.2/32, 2a07:b944::2:2/128
DNS = 10.2.0.1
MTU = 1420
PostUp = echo must never execute

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.10:51820
PersistentKeepalive = 25
`;

test("recognizes Proton WireGuard .conf and OpenVPN .conf profiles", async () => {
	const directory = await mkdtemp(path.join(os.tmpdir(), "proton-profiles-"));
	try {
		await writeFile(path.join(directory, "wg-NL-FREE-1.conf"), wireGuardProfile);
		await writeFile(path.join(directory, "server.conf"), "client\nremote vpn.example.test 1194\ndev tun\n");
		await writeFile(path.join(directory, "README.conf"), "not a VPN profile\n");
		const profiles = await listTunnelProfiles(directory);
		assert.deepEqual(
			profiles.map(({ configName, protocol, interfaceIp, interfaceAddress, mtu }) => ({ configName, protocol, interfaceIp, interfaceAddress, mtu })),
			[
				{ configName: "server.conf", protocol: "openvpn", interfaceIp: undefined, interfaceAddress: undefined, mtu: undefined },
				{ configName: "wg-NL-FREE-1.conf", protocol: "wireguard", interfaceIp: "10.2.0.2", interfaceAddress: "10.2.0.2/32", mtu: 1420 },
			],
		);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("strips WireGuard-only metadata and shell hooks before wg setconf", () => {
	const stripped = stripWireGuardConfig(wireGuardProfile);
	assert.match(stripped, /\[Interface\]/);
	assert.match(stripped, /PrivateKey = A{43}=/);
	assert.match(stripped, /\[Peer\]/);
	assert.match(stripped, /AllowedIPs = 0\.0\.0\.0\/0, ::\/0/);
	assert.doesNotMatch(stripped, /Address|DNS|MTU|PostUp/);
});

test("fails when the profile directory has no supported VPN files", async () => {
	const directory = await mkdtemp(path.join(os.tmpdir(), "proton-profiles-empty-"));
	try {
		await writeFile(path.join(directory, "README.conf"), "not a VPN profile\n");
		await assert.rejects(listTunnelProfiles(directory), /No supported OpenVPN/);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});
