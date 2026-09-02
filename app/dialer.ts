import net from "net";
// @ts-ignore — the native addon is built by the tundialer-native npm hook.
import tundialer from "../tundialer-native/index.js";

/**
 * Open an IPv4 TCP socket constrained to one OpenVPN interface and policy
 * routing mark. The native call is synchronous so the returned fd is already
 * connected when Node adopts it; this function runs in the short-lived
 * connection path and never mutates process-global routing state.
 */
export async function connectViaDialer(
	dev: string,
	dstIp: string,
	port: number,
	routingMark = 0,
	sourceIp = "",
	timeoutMs = 30_000,
): Promise<net.Socket> {
	const fd = typeof tundialer.connectAsync === "function"
		? await tundialer.connectAsync(dev, dstIp, port, routingMark, sourceIp, timeoutMs)
		: tundialer.connect(dev, dstIp, port, routingMark, sourceIp, timeoutMs);
	if (!Number.isInteger(fd) || fd < 0) throw new Error(`Failed to connect via tundialer on ${dev}`);
	return new net.Socket({ fd, readable: true, writable: true });
}
