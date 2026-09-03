import { spawn, spawnSync, type ChildProcess } from "child_process";
import { existsSync, promises as fs, readFileSync } from "fs";
import dns from "dns";
import net from "net";
import path from "path";
import { URL } from "url";

import { resetCredentials, type OpenVpnCredentials } from "./browser.ts";
import { connectViaDialer } from "./dialer.ts";
import { listTunnelProfiles, stripWireGuardConfig, type TunnelProfile, type TunnelProtocol } from "./tunnel_profiles.ts";

/**
 * A multi-tunnel Proton HTTP CONNECT proxy.
 *
 * Every OpenVPN or WireGuard profile receives a stable tunnel interface, its
 * own route table, a per-socket fwmark, and an individual HTTP proxy listener.
 * The listener on BASE_PROXY_PORT rotates only across healthy tunnels. Route
 * isolation is intentionally per socket; no global default route is ever
 * changed after startup.
 */

type TunnelState = "starting" | "ready" | "backoff" | "stopped";

interface TunnelInfo {
	configPath: string;
	configName: string;
	protocol: TunnelProtocol;
	port: number;
	devName: string;
	routingTable: number;
	routingMark: number;
	routingRulePriority: number;
	state: TunnelState;
	interfaceIp?: string;
	interfaceAddress?: string;
	mtu?: number;
	process?: ChildProcess;
}

interface OpenVpnExit {
	code: number | null;
	signal: NodeJS.Signals | null;
	authFailed: boolean;
	logs: string[];
}

interface OpenVpnRun {
	child: ChildProcess;
	ready: Promise<void>;
	exited: Promise<OpenVpnExit>;
}

interface WireGuardRun {
	interfaceName: string;
}

class OpenVpnError extends Error {
	readonly authFailed: boolean;

	constructor(message: string, authFailed = false) {
		super(message);
		this.name = "OpenVpnError";
		this.authFailed = authFailed;
	}
}

const ENV = process.env;
const AUTH_FILE_PATH = ENV.OPENVPN_AUTH_FILE || "/etc/openvpn/auth.txt";
const OVPN_CONFIG_DIR = ENV.OVPN_CONFIG_DIR || "/etc/openvpn/configs";
const OPENVPN_BIN = ENV.OPENVPN_BIN || "openvpn";
const WIREGUARD_BIN = ENV.WIREGUARD_BIN || "wg";
const IP_BIN = ENV.IP_BIN || "ip";
const BASE_PORT = integerFromEnv("BASE_PROXY_PORT", 8100);
const MAX_CONNECTIONS = integerFromEnv("MAX_CONNECTIONS", 0);
const PORT_GAP = integerFromEnv("PORT_GAP", 1);
const CONNECT_BACKLOG = integerFromEnv("PROXY_BACKLOG", 128);
const CONNECT_TIMEOUT_MS = integerFromEnv("CONNECT_TIMEOUT_MS", 30_000);
const TUN_IP_WAIT_MS = integerFromEnv("TUN_IP_WAIT_MS", 30_000);
const STARTUP_TIMEOUT_MS = integerFromEnv("STARTUP_TIMEOUT_MS", 120_000);
const RESTART_INITIAL_DELAY_MS = integerFromEnv("RESTART_INITIAL_DELAY_MS", 1_000);
const RESTART_MAX_DELAY_MS = integerFromEnv("RESTART_MAX_DELAY_MS", 30_000);
const WIREGUARD_HEALTH_CHECK_INTERVAL_MS = integerFromEnv("WIREGUARD_HEALTH_CHECK_INTERVAL_MS", 5_000);
const ROUTING_TABLE_BASE = integerFromEnv("ROUTING_TABLE_BASE", 10_000);
const ROUTING_MARK_BASE = integerFromEnv("ROUTING_MARK_BASE", 0x5a0000);
const ROUTING_RULE_PRIORITY_BASE = integerFromEnv("ROUTING_RULE_PRIORITY_BASE", 12_000);
const REQUIRE_TUN_IP = booleanFromEnv("REQUIRE_TUN_IP", true);
const RESET_CREDENTIALS_ON_START = booleanFromEnv("RESET_CREDENTIALS_ON_START", false);
const DNS_SERVERS_OVERRIDE = (ENV.DNS_SERVERS_OVERRIDE || "").trim();

let stopping = false;
let resolveShutdown!: () => void;
const shutdownSignal = new Promise<void>((resolve) => {
	resolveShutdown = resolve;
});
const proxyServers = new Set<net.Server>();
const activeOpenVpn = new Set<ChildProcess>();
let credentialRefresh: Promise<void> | undefined;

function integerFromEnv(name: string, fallback: number): number {
	const raw = ENV[name];
	if (raw === undefined || raw.trim() === "") return fallback;
	const parsed = Number(raw.trim());
	return Number.isSafeInteger(parsed) ? parsed : Number.NaN;
}

function booleanFromEnv(name: string, fallback: boolean): boolean {
	const value = (ENV[name] || "").trim().toLowerCase();
	if (!value) return fallback;
	return value === "1" || value === "true" || value === "yes" || value === "on";
}

function sleep(milliseconds: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitOrShutdown(milliseconds: number): Promise<void> {
	await Promise.race([sleep(milliseconds), shutdownSignal]);
}

function validateRuntimeOptions(): void {
	if (!Number.isInteger(BASE_PORT) || BASE_PORT < 1 || BASE_PORT > 65535) {
		throw new Error(`BASE_PROXY_PORT must be between 1 and 65535 (received ${BASE_PORT})`);
	}
	if (!Number.isInteger(MAX_CONNECTIONS) || MAX_CONNECTIONS < 0) {
		throw new Error(`MAX_CONNECTIONS must be zero or a positive integer (received ${MAX_CONNECTIONS})`);
	}
	if (!Number.isInteger(PORT_GAP) || PORT_GAP < 1) {
		throw new Error(`PORT_GAP must be a positive integer (received ${PORT_GAP})`);
	}
	if (!Number.isInteger(CONNECT_TIMEOUT_MS) || CONNECT_TIMEOUT_MS < 1 || CONNECT_TIMEOUT_MS > 300_000) {
		throw new Error(`CONNECT_TIMEOUT_MS must be between 1 and 300000 (received ${CONNECT_TIMEOUT_MS})`);
	}
	for (const [name, value] of [
		["PROXY_BACKLOG", CONNECT_BACKLOG],
		["TUN_IP_WAIT_MS", TUN_IP_WAIT_MS],
		["STARTUP_TIMEOUT_MS", STARTUP_TIMEOUT_MS],
		["RESTART_INITIAL_DELAY_MS", RESTART_INITIAL_DELAY_MS],
		["RESTART_MAX_DELAY_MS", RESTART_MAX_DELAY_MS],
		["WIREGUARD_HEALTH_CHECK_INTERVAL_MS", WIREGUARD_HEALTH_CHECK_INTERVAL_MS],
	] as const) {
		if (!Number.isSafeInteger(value) || value < 1) {
			throw new Error(`${name} must be a positive integer (received ${value})`);
		}
	}
	if (RESTART_MAX_DELAY_MS < RESTART_INITIAL_DELAY_MS) {
		throw new Error("RESTART_MAX_DELAY_MS must be at least RESTART_INITIAL_DELAY_MS");
	}
	for (const [name, value] of [
		["ROUTING_TABLE_BASE", ROUTING_TABLE_BASE],
		["ROUTING_MARK_BASE", ROUTING_MARK_BASE],
		["ROUTING_RULE_PRIORITY_BASE", ROUTING_RULE_PRIORITY_BASE],
	] as const) {
		if (!Number.isSafeInteger(value) || value < 1 || value > 0xffffffff) {
			throw new Error(`${name} must be an unsigned positive 32-bit integer (received ${value})`);
		}
	}
}

async function ensureTunDevice(): Promise<void> {
	if (existsSync("/dev/net/tun")) return;
	if (!existsSync("/dev/net")) await fs.mkdir("/dev/net", { recursive: true });
	const create = spawnSync("mknod", ["/dev/net/tun", "c", "10", "200"]);
	if (create.status !== 0 && !existsSync("/dev/net/tun")) {
		throw new Error("Unable to create /dev/net/tun; pass the device into the container and grant NET_ADMIN");
	}
	spawnSync("chmod", ["0666", "/dev/net/tun"]);
	if (!existsSync("/dev/net/tun")) throw new Error("Cannot access /dev/net/tun");
}

function readAuth(): OpenVpnCredentials {
	const lines = readFileSync(AUTH_FILE_PATH, "utf8")
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter(Boolean);
	if (lines.length < 2) throw new Error(`Invalid OpenVPN credential file: ${AUTH_FILE_PATH}`);
	return { username: lines[0], password: lines[1] };
}

async function writeAuth(credentials: OpenVpnCredentials): Promise<void> {
	if (!credentials.username || !credentials.password) throw new Error("OpenVPN credentials cannot be empty");
	await fs.mkdir(path.dirname(AUTH_FILE_PATH), { recursive: true });
	const temporaryPath = `${AUTH_FILE_PATH}.tmp-${process.pid}-${Date.now()}`;
	try {
		await fs.writeFile(temporaryPath, `${credentials.username}\n${credentials.password}\n`, { mode: 0o600 });
		await fs.chmod(temporaryPath, 0o600);
		await fs.rename(temporaryPath, AUTH_FILE_PATH);
	} finally {
		await fs.rm(temporaryPath, { force: true }).catch(() => undefined);
	}
}

async function ensureInitialAuth(): Promise<void> {
	if (RESET_CREDENTIALS_ON_START) {
		console.log("[auth] resetting Proton OpenVPN credentials on explicit startup request");
		await writeAuth(await resetCredentials());
		return;
	}
	if (existsSync(AUTH_FILE_PATH)) {
		readAuth();
		return;
	}
	if (!ENV.PVPN_USERNAME || !ENV.PVPN_PASSWORD) {
		throw new Error("PVPN_USERNAME and PVPN_PASSWORD are required when no OpenVPN auth file exists");
	}
	await writeAuth({ username: ENV.PVPN_USERNAME, password: ENV.PVPN_PASSWORD });
}

async function refreshCredentialsIfUnchanged(snapshot: OpenVpnCredentials): Promise<void> {
	const current = readAuth();
	if (current.username !== snapshot.username || current.password !== snapshot.password) return;
	if (!credentialRefresh) {
		credentialRefresh = (async () => {
			console.warn("[auth] OpenVPN credentials were rejected; performing one account-wide Proton credential reset");
			await writeAuth(await resetCredentials());
			// Proton resets a shared OpenVPN credential pair. Deliberately restart
			// every existing tunnel so they all re-authenticate with the new pair.
			await Promise.all([...activeOpenVpn].map((child) => stopOpenVpn(child)));
			console.log("[auth] refreshed credentials and requested a clean restart for all tunnel workers");
		})().finally(() => {
			credentialRefresh = undefined;
		});
	}
	await credentialRefresh;
}

async function listConfigs(): Promise<TunnelProfile[]> {
	return listTunnelProfiles(OVPN_CONFIG_DIR);
}

function buildTunnels(configs: TunnelProfile[]): TunnelInfo[] {
	const selected = MAX_CONNECTIONS === 0 ? configs : configs.slice(0, MAX_CONNECTIONS);
	if (!selected.length) throw new Error("MAX_CONNECTIONS selected zero tunnel profiles");
	let openVpnIndex = 0;
	let wireGuardIndex = 0;
	return selected.map((config, index) => {
		const port = BASE_PORT + PORT_GAP * (index + 1);
		const routingTable = ROUTING_TABLE_BASE + index;
		const routingMark = ROUTING_MARK_BASE + index;
		const routingRulePriority = ROUTING_RULE_PRIORITY_BASE + index;
		if (port > 65535 || routingTable > 0xffffffff || routingMark > 0xffffffff || routingRulePriority > 0xffffffff) {
			throw new Error("Too many tunnel profiles for the configured port or routing identifier ranges");
		}
		return {
			configPath: config.configPath,
			configName: config.configName,
			protocol: config.protocol,
			port,
			devName: config.protocol === "wireguard" ? `wg${wireGuardIndex++}` : `tun${openVpnIndex++}`,
			routingTable,
			routingMark,
			routingRulePriority,
			state: "starting",
			interfaceIp: config.interfaceIp,
			interfaceAddress: config.interfaceAddress,
			mtu: config.mtu,
		};
	});
}

async function overrideDns(): Promise<void> {
	if (!DNS_SERVERS_OVERRIDE) return;
	const servers = DNS_SERVERS_OVERRIDE.split(",").map((server) => server.trim()).filter(Boolean);
	if (!servers.length) return;
	await fs.writeFile("/etc/resolv.conf", ["# proton-proxy override", ...servers.map((server) => `nameserver ${server}`)].join("\n") + "\n");
}

function parseIPv4(value: string): string | undefined {
	return value.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/)?.[0];
}

function tunnelIpv4(device: string): string | undefined {
	try {
		const result = spawnSync(IP_BIN, ["-j", "-4", "address", "show", "dev", device], {
			encoding: "utf8",
			stdio: ["ignore", "pipe", "ignore"],
		});
		if (result.status === 0 && result.stdout?.trim()) {
			const interfaces = JSON.parse(result.stdout) as Array<{ addr_info?: Array<{ family?: string; local?: string }> }>;
			return interfaces.flatMap((entry) => entry.addr_info || []).find((entry) => entry.family === "inet" && entry.local)?.local;
		}
	} catch {
		// Fall through to text parsing for older iproute2 versions.
	}
	try {
		const result = spawnSync(IP_BIN, ["-4", "-o", "address", "show", "dev", device], {
			encoding: "utf8",
			stdio: ["ignore", "pipe", "ignore"],
		});
		return parseIPv4(result.stdout || "");
	} catch {
		return undefined;
	}
}

async function waitForTunnelIpv4(tunnel: TunnelInfo): Promise<void> {
	if (tunnel.protocol === "wireguard") {
		tunnel.interfaceIp = tunnelIpv4(tunnel.devName) || tunnel.interfaceIp;
		if (REQUIRE_TUN_IP && !tunnel.interfaceIp) throw new OpenVpnError(`No IPv4 address appeared on ${tunnel.devName}`);
		return;
	}
	const deadline = Date.now() + TUN_IP_WAIT_MS;
	while (!stopping) {
		const address = tunnelIpv4(tunnel.devName) || tunnel.interfaceIp;
		if (address) {
			tunnel.interfaceIp = address;
			return;
		}
		if (!tunnel.process || tunnel.process.exitCode !== null || tunnel.process.signalCode !== null || Date.now() >= deadline) break;
		await waitOrShutdown(250);
	}
	if (REQUIRE_TUN_IP) throw new OpenVpnError(`No IPv4 address appeared on ${tunnel.devName}`);
}

function runIp(arguments_: string[], description: string, allowFailure = false): void {
	const result = spawnSync(IP_BIN, arguments_, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
	if (result.status === 0 || allowFailure) return;
	const output = `${result.stdout || ""}\n${result.stderr || ""}`.trim();
	const spawnError = result.error instanceof Error ? `: ${result.error.message}` : "";
	throw new Error(`${description} failed${output ? `: ${output}` : spawnError}`);
}

function runWireGuard(arguments_: string[], description: string, allowFailure = false): string {
	const result = spawnSync(WIREGUARD_BIN, arguments_, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
	if (result.status === 0) return result.stdout || "";
	if (allowFailure) return result.stdout || "";
	const output = `${result.stdout || ""}\n${result.stderr || ""}`.trim();
	const spawnError = result.error instanceof Error ? `: ${result.error.message}` : "";
	throw new Error(`${description} failed${output ? `: ${output}` : spawnError}`);
}

function setSysctl(name: string, value: string): void {
	const procPath = `/proc/sys/${name.replace(/\./g, "/")}`;
	try {
		if (readFileSync(procPath, "utf8").trim() === value) return;
	} catch {
		// Fall through to the write so the resulting warning explains whether the
		// runtime lacks this sysctl entirely or merely denies the update.
	}
	const result = spawnSync("sysctl", ["-q", "-w", `${name}=${value}`], {
		encoding: "utf8",
		stdio: ["ignore", "pipe", "pipe"],
	});
	if (result.status === 0) return;
	const detail = `${result.stdout || ""}\n${result.stderr || ""}`.trim();
	console.warn(`[routing] unable to set ${name}=${value}${detail ? `: ${detail}` : ""}`);
}

function wireGuardInterfaceExists(device: string): boolean {
	const result = spawnSync(IP_BIN, ["link", "show", "dev", device], {
		encoding: "utf8",
		stdio: ["ignore", "pipe", "ignore"],
	});
	return result.status === 0;
}

function wireGuardInterfaceIsUp(device: string): boolean {
	const result = spawnSync(IP_BIN, ["-o", "link", "show", "dev", device], {
		encoding: "utf8",
		stdio: ["ignore", "pipe", "ignore"],
	});
	return result.status === 0 && /<[^>]*\bUP\b[^>]*>/.test(result.stdout || "");
}

function wireGuardInterfaceIsKernelDevice(device: string): boolean {
	const result = spawnSync(IP_BIN, ["-d", "link", "show", "dev", device], {
		encoding: "utf8",
		stdio: ["ignore", "pipe", "ignore"],
	});
	return result.status === 0 && /\bwireguard\b/i.test(result.stdout || "");
}

function wireGuardConfigured(device: string): boolean {
	const result = spawnSync(WIREGUARD_BIN, ["show", device, "peers"], {
		encoding: "utf8",
		stdio: ["ignore", "pipe", "ignore"],
	});
	if (result.status !== 0) return false;
	return (result.stdout || "").split(/\s+/).some((peer) => peer.length > 0);
}

function ensureWireGuardBinary(): void {
	const result = spawnSync(WIREGUARD_BIN, ["--version"], {
		encoding: "utf8",
		stdio: ["ignore", "pipe", "pipe"],
	});
	if (result.status !== 0) {
		const detail = result.error instanceof Error ? `: ${result.error.message}` : "";
		throw new Error(`WireGuard profiles require the '${WIREGUARD_BIN}' binary (install wireguard-tools)${detail}`);
	}
}

function removeWireGuardInterface(device: string): void {
	// `ip link del` also removes addresses and the kernel WireGuard UDP socket.
	// It is intentionally idempotent so failed partial startups and shutdowns
	// cannot leave a stale interface that receives a later tunnel's traffic.
	if (!wireGuardInterfaceExists(device)) {
		return;
	}
	if (!wireGuardInterfaceIsKernelDevice(device)) {
		console.warn(`[wireguard] refusing to remove non-WireGuard interface ${device}`);
		return;
	}
	runIp(["link", "del", "dev", device], `remove ${device} WireGuard interface`, true);
}

async function startWireGuard(tunnel: TunnelInfo): Promise<WireGuardRun> {
	const source = await fs.readFile(tunnel.configPath, "utf8");
	const stripped = stripWireGuardConfig(source);
	if (!stripped.includes("[Interface]")) throw new Error(`WireGuard profile ${tunnel.configName} has no [Interface] section`);
	if (!stripped.includes("[Peer]")) throw new Error(`WireGuard profile ${tunnel.configName} has no [Peer] section`);

	removeWireGuardInterface(tunnel.devName);
	// Never carry an address from a previous interface generation into a new
	// route. The address below is re-read from the freshly created device.
	tunnel.interfaceIp = undefined;
	runIp(["link", "add", "dev", tunnel.devName, "type", "wireguard"], `create ${tunnel.devName} WireGuard interface`);
	const temporaryPath = `/run/proton-proxy-${process.pid}-${tunnel.devName}-${Date.now()}.conf`;
	try {
		await fs.writeFile(temporaryPath, stripped, { mode: 0o600 });
		await fs.chmod(temporaryPath, 0o600);
		runWireGuard(["setconf", tunnel.devName, temporaryPath], `configure ${tunnel.devName} WireGuard peer`);
		// Keep the host's main route for encrypted UDP transport. Application
		// sockets use routingMark and the private table installed below; leaving
		// the WireGuard interface fwmark at zero prevents recursive endpoint
		// routing when several full-tunnel interfaces coexist.
		runWireGuard(["set", tunnel.devName, "fwmark", "0"], `clear ${tunnel.devName} WireGuard transport mark`);
		if (tunnel.interfaceAddress) {
			runIp(["-4", "address", "replace", tunnel.interfaceAddress, "dev", tunnel.devName], `assign ${tunnel.devName} IPv4 address`);
		}
		if (tunnel.mtu) runIp(["link", "set", "dev", tunnel.devName, "mtu", String(tunnel.mtu)], `set ${tunnel.devName} MTU`);
		runIp(["link", "set", "dev", tunnel.devName, "up"], `activate ${tunnel.devName} WireGuard interface`);
		tunnel.interfaceIp = tunnelIpv4(tunnel.devName);
		if (REQUIRE_TUN_IP && !tunnel.interfaceIp) throw new Error(`No IPv4 address appeared on ${tunnel.devName}`);
		console.log(`[wireguard] launched ${tunnel.configName} on ${tunnel.devName}`);
		return { interfaceName: tunnel.devName };
	} catch (error) {
		removeWireGuardInterface(tunnel.devName);
		throw error;
	} finally {
		await fs.rm(temporaryPath, { force: true }).catch(() => undefined);
	}
}

async function waitForWireGuardFailure(tunnel: TunnelInfo): Promise<void> {
	while (!stopping) {
		await waitOrShutdown(WIREGUARD_HEALTH_CHECK_INTERVAL_MS);
		if (stopping) return;
		if (!wireGuardInterfaceIsUp(tunnel.devName) || !wireGuardConfigured(tunnel.devName)) {
			throw new Error(`WireGuard interface ${tunnel.devName} disappeared or lost its peer configuration`);
		}
	}
}

function clearTunnelRoute(tunnel: TunnelInfo): void {
	const table = String(tunnel.routingTable);
	const mark = `0x${tunnel.routingMark.toString(16)}/0xffffffff`;
	// Match every selector we installed. Deleting by priority alone could
	// remove an unrelated host policy rule when an operator accidentally
	// chooses a colliding base range.
	runIp(
		["-4", "rule", "del", "priority", String(tunnel.routingRulePriority), "fwmark", mark, "lookup", table],
		`remove ${tunnel.devName} policy rule`,
		true,
	);
	// Do not flush the whole numeric table: it might be an operator's table if
	// they configured a conflicting base. The route created below is the only
	// route this service owns.
	runIp(["-4", "route", "del", "default", "dev", tunnel.devName, "table", table], `remove ${tunnel.devName} default route`, true);
}

function configureTunnelRoute(tunnel: TunnelInfo): void {
	clearTunnelRoute(tunnel);
	const route = ["-4", "route", "replace", "default", "dev", tunnel.devName];
	if (tunnel.interfaceIp) route.push("src", tunnel.interfaceIp);
	route.push("table", String(tunnel.routingTable));
	runIp(route, `install ${tunnel.devName} default route`);
	runIp(
		[
			"-4",
			"rule",
			"add",
			"priority",
			String(tunnel.routingRulePriority),
			"fwmark",
			`0x${tunnel.routingMark.toString(16)}/0xffffffff`,
			"lookup",
			String(tunnel.routingTable),
		],
		`install ${tunnel.devName} policy rule`,
	);
	// A marked packet deliberately arrives through a private route table. Strict
	// rp_filter would discard its reply before userspace sees it.
	setSysctl("net.ipv4.conf.all.src_valid_mark", "1");
	setSysctl(`net.ipv4.conf.${tunnel.devName}.rp_filter`, "0");
	console.log(`[routing] ${tunnel.devName}: mark=0x${tunnel.routingMark.toString(16)} table=${tunnel.routingTable}`);
}

function openVpnArgs(tunnel: TunnelInfo): string[] {
	return [
		"--config",
		tunnel.configPath,
		"--dev",
		tunnel.devName,
		"--dev-type",
		"tun",
		"--auth-user-pass",
		AUTH_FILE_PATH,
		"--auth-nocache",
		"--auth-retry",
		"nointeract",
		"--float",
		"--pull-filter",
		"ignore",
		"route-ipv6",
		"--pull-filter",
		"ignore",
		"ifconfig-ipv6",
		"--pull-filter",
		"ignore",
		"dhcp-option",
		"--pull-filter",
		"ignore",
		"redirect-gateway",
		"--route-nopull",
		"--route-noexec",
		"--verb",
		"3",
	];
}

function startOpenVpn(tunnel: TunnelInfo): OpenVpnRun {
	const child = spawn(OPENVPN_BIN, openVpnArgs(tunnel), { stdio: ["ignore", "pipe", "pipe"] });
	tunnel.process = child;
	activeOpenVpn.add(child);

	let readySettled = false;
	let exitSettled = false;
	let authFailed = false;
	let authStopRequested = false;
	let logs: string[] = [];
	let stdoutRemainder = "";
	let stderrRemainder = "";
	let resolveReady!: () => void;
	let rejectReady!: (reason: Error) => void;
	let resolveExited!: (value: OpenVpnExit) => void;
	const ready = new Promise<void>((resolve, reject) => {
		resolveReady = resolve;
		rejectReady = reject;
	});
	const exited = new Promise<OpenVpnExit>((resolve) => {
		resolveExited = resolve;
	});

	const finish = (code: number | null, signal: NodeJS.Signals | null, startupError?: Error) => {
		if (exitSettled) return;
		exitSettled = true;
		activeOpenVpn.delete(child);
		if (tunnel.process === child) tunnel.process = undefined;
		if (!readySettled) {
			readySettled = true;
			rejectReady(
				startupError || new OpenVpnError(
					`OpenVPN ${tunnel.configName} exited before initialization (code=${code}, signal=${signal})\n${logs.join("\n")}`,
					authFailed,
				),
			);
		}
		resolveExited({ code, signal, authFailed, logs });
	};
	const consume = (data: Buffer, source: "stdout" | "stderr") => {
		const remainder = source === "stdout" ? stdoutRemainder : stderrRemainder;
		const lines = `${remainder}${data.toString("utf8")}`.split(/\r?\n/);
		const trailing = lines.pop() || "";
		if (source === "stdout") stdoutRemainder = trailing;
		else stderrRemainder = trailing;
		for (const rawLine of lines) {
			const line = rawLine.trim();
			if (!line) continue;
			logs.push(line);
			if (logs.length > 200) logs = logs.slice(-200);
			console.log(`[openvpn:${tunnel.devName}:${source}] ${line}`);
			if (line.includes("AUTH_FAILED")) {
				authFailed = true;
				// `--auth-retry nointeract` can keep OpenVPN reconnecting forever
				// after an authentication failure. Stop this worker explicitly so
				// the supervisor can refresh the account-wide credential once and
				// restart every profile with the new pair.
				if (!authStopRequested && !stopping && child.exitCode === null) {
					authStopRequested = true;
					try {
						child.kill("SIGTERM");
					} catch {
						// The process may have exited between the check and kill.
					}
				}
			}
			if (line.includes("net_addr_v4_add")) tunnel.interfaceIp = parseIPv4(line) || tunnel.interfaceIp;
			if (line.includes("Initialization Sequence Completed") && !readySettled) {
				readySettled = true;
				resolveReady();
			}
		}
	};
	const flushPartialLines = () => {
		if (stdoutRemainder) {
			const partial = stdoutRemainder;
			stdoutRemainder = "";
			consume(Buffer.from(`${partial}\n`), "stdout");
		}
		if (stderrRemainder) {
			const partial = stderrRemainder;
			stderrRemainder = "";
			consume(Buffer.from(`${partial}\n`), "stderr");
		}
	};

	child.stdout?.on("data", (data: Buffer) => consume(data, "stdout"));
	child.stderr?.on("data", (data: Buffer) => consume(data, "stderr"));
	child.once("error", (error) => finish(null, null, error));
	child.once("exit", (code, signal) => {
		flushPartialLines();
		finish(code, signal);
	});
	console.log(`[openvpn] launched ${tunnel.configName} on ${tunnel.devName}`);
	return { child, ready, exited };
}

async function stopOpenVpn(child: ChildProcess): Promise<void> {
	if (child.exitCode !== null || child.signalCode !== null) return;
	try {
		child.kill("SIGTERM");
	} catch {
		return;
	}
	await Promise.race([new Promise<void>((resolve) => child.once("exit", () => resolve())), sleep(5_000)]);
	if (child.exitCode === null && child.signalCode === null) {
		try {
			child.kill("SIGKILL");
		} catch {
			// It can exit between the check and kill.
		}
	}
}

function tunnelReady(tunnel: TunnelInfo): boolean {
	return tunnel.state === "ready" && (!REQUIRE_TUN_IP || Boolean(tunnel.interfaceIp));
}

async function superviseTunnel(tunnel: TunnelInfo): Promise<void> {
	let retryDelay = Math.max(100, RESTART_INITIAL_DELAY_MS);
	while (!stopping) {
		tunnel.state = "starting";
		if (tunnel.protocol === "openvpn") tunnel.interfaceIp = undefined;
		const credentialSnapshot = tunnel.protocol === "openvpn" ? readAuth() : undefined;
		let run: OpenVpnRun | undefined;
		let wireGuardRun: WireGuardRun | undefined;
		try {
			if (tunnel.protocol === "openvpn") {
				run = startOpenVpn(tunnel);
				await run.ready;
			} else {
				wireGuardRun = await startWireGuard(tunnel);
			}
			await waitForTunnelIpv4(tunnel);
			configureTunnelRoute(tunnel);
			if (stopping) break;
			tunnel.state = "ready";
			retryDelay = Math.max(100, RESTART_INITIAL_DELAY_MS);
			console.log(`[tunnel] ready ${tunnel.configName}: ${tunnel.devName} (${tunnel.interfaceIp || "no IPv4"})`);

			if (run) {
				const exited = await run.exited;
				if (!stopping && exited.authFailed && credentialSnapshot) await refreshCredentialsIfUnchanged(credentialSnapshot);
			} else {
				await waitForWireGuardFailure(tunnel);
			}
		} catch (error) {
			console.error(`[tunnel] ${tunnel.configName} failed: ${error instanceof Error ? error.message : String(error)}`);
			if (error instanceof OpenVpnError && error.authFailed && credentialSnapshot && !stopping) {
				try {
					await refreshCredentialsIfUnchanged(credentialSnapshot);
				} catch (refreshError) {
					console.error(`[auth] credential reset failed: ${refreshError instanceof Error ? refreshError.message : String(refreshError)}`);
				}
			}
		} finally {
			tunnel.state = stopping ? "stopped" : "backoff";
			clearTunnelRoute(tunnel);
			if (run) await stopOpenVpn(run.child);
			if (wireGuardRun) removeWireGuardInterface(wireGuardRun.interfaceName);
		}
		if (stopping) break;
		console.warn(`[tunnel] retrying ${tunnel.configName} in ${retryDelay}ms`);
		await waitOrShutdown(retryDelay);
		retryDelay = Math.min(RESTART_MAX_DELAY_MS, retryDelay * 2);
	}
	tunnel.state = "stopped";
}

function createTunnelProxy(tunnel: TunnelInfo): Promise<void> {
	const server = net.createServer({ allowHalfOpen: false }, (client) => {
		readProxyRequest(client, () => tunnel);
	});
	proxyServers.add(server);
	server.on("error", (error) => console.error(`[proxy:${tunnel.port}] ${error.message}`));
	server.listen({ host: "0.0.0.0", port: tunnel.port, backlog: CONNECT_BACKLOG });
	return new Promise((resolve, reject) => {
		server.once("listening", () => {
			console.log(`[proxy] ${tunnel.configName} listening on ${tunnel.port}`);
			resolve();
		});
		server.once("error", reject);
	});
}

function createRotatingProxy(tunnels: TunnelInfo[]): Promise<void> {
	let nextTunnel = 0;
	const pickTunnel = (): TunnelInfo | undefined => {
		for (let attempt = 0; attempt < tunnels.length; attempt += 1) {
			const tunnel = tunnels[nextTunnel % tunnels.length];
			nextTunnel += 1;
			if (tunnelReady(tunnel)) return tunnel;
		}
		return undefined;
	};
	const server = net.createServer({ allowHalfOpen: false }, (client) => readProxyRequest(client, pickTunnel));
	proxyServers.add(server);
	server.on("error", (error) => console.error(`[proxy:${BASE_PORT}] ${error.message}`));
	server.listen({ host: "0.0.0.0", port: BASE_PORT, backlog: CONNECT_BACKLOG });
	return new Promise((resolve, reject) => {
		server.once("listening", () => {
			console.log(`[proxy] rotating listener on ${BASE_PORT} across ${tunnels.length} tunnel workers`);
			resolve();
		});
		server.once("error", reject);
	});
}

function rejectUnavailable(client: net.Socket): void {
	if (!client.destroyed) client.end("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\nNo Proton tunnel is ready");
}

function readProxyRequest(client: net.Socket, pickTunnel: () => TunnelInfo | undefined): void {
	let buffered = new Uint8Array(0);
	const cleanup = () => {
		client.off("data", onData);
		client.off("timeout", onTimeout);
	};
	const onTimeout = () => {
		cleanup();
		client.destroy();
	};
	const onData = (chunk: Uint8Array) => {
		const joined = new Uint8Array(buffered.byteLength + chunk.byteLength);
		joined.set(buffered);
		joined.set(chunk, buffered.byteLength);
		buffered = joined;
		if (buffered.length > 64 * 1024) {
			cleanup();
			client.destroy();
			return;
		}
		const headerEnd = findHeaderDelimiter(buffered);
		if (headerEnd < 0) return;
		cleanup();
		client.pause();
		void handleProxyRequest(client, buffered, headerEnd, pickTunnel);
	};
	client.setTimeout(15_000);
	client.on("data", onData);
	client.once("error", cleanup);
	client.once("close", cleanup);
	client.once("timeout", onTimeout);
}

function findHeaderDelimiter(data: Uint8Array): number {
	for (let index = 0; index + 3 < data.byteLength; index += 1) {
		if (data[index] === 13 && data[index + 1] === 10 && data[index + 2] === 13 && data[index + 3] === 10) {
			return index;
		}
	}
	return -1;
}

function connectTarget(value: string, defaultPort: number): { host: string; port: number } | undefined {
	try {
		const target = new URL(`http://${value}`);
		if (target.username || target.password || !target.hostname || target.pathname !== "/" || target.search || target.hash) return undefined;
		const port = target.port ? Number.parseInt(target.port, 10) : defaultPort;
		if (!Number.isInteger(port) || port < 1 || port > 65535) return undefined;
		return { host: target.hostname, port };
	} catch {
		return undefined;
	}
}

async function writeToSocket(socket: net.Socket, data: string | Uint8Array): Promise<void> {
	await new Promise<void>((resolve, reject) => {
		socket.write(data, (error) => (error ? reject(error) : resolve()));
	});
}

async function handleProxyRequest(
	client: net.Socket,
	firstChunk: Uint8Array,
	headerEnd: number,
	pickTunnel: () => TunnelInfo | undefined,
): Promise<void> {
	const tunnel = pickTunnel();
	if (!tunnel || !tunnelReady(tunnel)) {
		rejectUnavailable(client);
		return;
	}
	const headerText = Buffer.from(firstChunk.subarray(0, headerEnd)).toString("latin1");
	const firstLine = headerText.split("\r\n", 1)[0] || "";
	const rest = firstChunk.subarray(headerEnd + 4);
	let target: { host: string; port: number } | undefined;
	let initialData: Uint8Array = new Uint8Array(0);
	let isConnect = false;

	const connectMatch = /^CONNECT\s+([^\s]+)\s+HTTP\/1\.[01]$/i.exec(firstLine);
	if (connectMatch) {
		target = connectTarget(connectMatch[1], 443);
		initialData = rest;
		isConnect = true;
	} else {
		const requestMatch = /^[A-Z]+\s+(https?:\/\/[^\s]+)\s+HTTP\/1\.[01]$/i.exec(firstLine);
		if (requestMatch) {
			try {
				const url = new URL(requestMatch[1]);
				if (url.protocol === "http:") {
					target = { host: url.hostname, port: url.port ? Number.parseInt(url.port, 10) : 80 };
					initialData = firstChunk;
				}
			} catch {
				// Invalid absolute HTTP URL below falls through to a closed socket.
			}
		}
	}
	if (!target || !target.host || !Number.isInteger(target.port) || target.port < 1 || target.port > 65535) {
		client.destroy();
		return;
	}

	try {
		const destinationIp = net.isIP(target.host)
			? target.host
			: (await dns.promises.lookup(target.host, { family: 4 })).address;
		if (!net.isIPv4(destinationIp)) throw new Error("only IPv4 destinations are supported by the tunnel dialer");
		const remote = await connectViaDialer(
			tunnel.devName,
			destinationIp,
			target.port,
			tunnel.routingMark,
			tunnel.interfaceIp,
			CONNECT_TIMEOUT_MS,
		);
		if (client.destroyed) {
			remote.destroy();
			return;
		}
		remote.once("error", () => client.destroy());
		remote.once("close", () => client.destroy());
		client.once("error", () => remote.destroy());
		client.once("close", () => remote.destroy());

		if (isConnect) await writeToSocket(client, "HTTP/1.1 200 Connection Established\r\n\r\n");
		if (initialData.length) await writeToSocket(remote, initialData);
		client.setTimeout(0);
		client.pipe(remote).pipe(client);
		console.log(`[proxy] ${tunnel.devName} -> ${target.host}(${destinationIp}):${target.port}`);
	} catch (error) {
		console.warn(`[proxy] ${tunnel.devName} connection to ${target.host}:${target.port} failed: ${error instanceof Error ? error.message : String(error)}`);
		client.destroy();
	}
}

async function waitForReadyTunnel(tunnels: TunnelInfo[]): Promise<void> {
	const deadline = Date.now() + STARTUP_TIMEOUT_MS;
	while (!stopping && Date.now() < deadline) {
		if (tunnels.some(tunnelReady)) return;
		await waitOrShutdown(250);
	}
	if (!tunnels.some(tunnelReady)) {
		throw new Error(`No VPN tunnel became ready within ${STARTUP_TIMEOUT_MS}ms (${tunnels.map((tunnel) => `${tunnel.configName}:${tunnel.state}`).join(", ")})`);
	}
}

async function shutdown(tunnels: TunnelInfo[]): Promise<void> {
	const firstShutdown = !stopping;
	stopping = true;
	if (firstShutdown) resolveShutdown();
	for (const server of proxyServers) {
		try {
			server.close();
		} catch {
			// A closed listener has nothing left to clean up.
		}
	}
	for (const tunnel of tunnels) clearTunnelRoute(tunnel);
	await Promise.all([...activeOpenVpn].map((child) => stopOpenVpn(child)));
	for (const tunnel of tunnels) {
		if (tunnel.protocol === "wireguard") removeWireGuardInterface(tunnel.devName);
	}
}

async function main(): Promise<void> {
	validateRuntimeOptions();
	await overrideDns();

	const tunnels = buildTunnels(await listConfigs());
	signalTunnels = tunnels;
	if (tunnels.some((tunnel) => tunnel.protocol === "wireguard")) ensureWireGuardBinary();
	if (tunnels.some((tunnel) => tunnel.protocol === "openvpn")) await ensureTunDevice();
	if (tunnels.some((tunnel) => tunnel.protocol === "openvpn")) await ensureInitialAuth();
	let workers: Promise<void>[] = [];
	try {
		await createRotatingProxy(tunnels);
		await Promise.all(tunnels.map(createTunnelProxy));
		workers = tunnels.map((tunnel) => superviseTunnel(tunnel));
		await waitForReadyTunnel(tunnels);
		const openVpnCount = tunnels.filter((tunnel) => tunnel.protocol === "openvpn").length;
		const wireGuardCount = tunnels.length - openVpnCount;
		console.log(`[service] ready: ${tunnels.length} concurrent VPN tunnel worker(s) (${openVpnCount} OpenVPN, ${wireGuardCount} WireGuard), rotating proxy on ${BASE_PORT}`);
		await Promise.all(workers);
	} finally {
		await shutdown(tunnels);
		await Promise.allSettled(workers);
	}
}

let signalTunnels: TunnelInfo[] = [];

async function run(): Promise<void> {
	try {
		await main();
	} catch (error) {
		console.error(error);
		process.exitCode = 1;
	}
}

process.once("SIGINT", () => void shutdown(signalTunnels));
process.once("SIGTERM", () => void shutdown(signalTunnels));
void run();
