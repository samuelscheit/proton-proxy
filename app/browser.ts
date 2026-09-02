import { config } from "dotenv";
import { existsSync, readFileSync, writeFileSync } from "fs";
import { dirname, join } from "path";
import { chromium, type Page } from "patchright";
import { fileURLToPath } from "url";

const filename = fileURLToPath(import.meta.url);
const directory = dirname(filename);

config({ path: join(directory, "..", ".env") });

const userDataDirectory = process.env.PROTON_USER_DATA_DIR || join(directory, "..", ".user_data");
const storagePath = join(userDataDirectory, "storage.json");
const resetEndpoint = "https://account.protonvpn.com/api/vpn/settings/reset";

export interface OpenVpnCredentials {
	username: string;
	password: string;
}

function sleep(milliseconds: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function accountCredentials(): { username: string; password: string } {
	const username = process.env.PROTON_USERNAME;
	const password = process.env.PROTON_PASSWORD;
	if (!username || !password) {
		throw new Error("PROTON_USERNAME and PROTON_PASSWORD are required to reset OpenVPN credentials");
	}
	return { username, password };
}

async function restoreBrowserStorage(page: Page, browser: Awaited<ReturnType<typeof chromium.launchPersistentContext>>): Promise<void> {
	if (!existsSync(storagePath)) return;
	try {
		const storage = JSON.parse(readFileSync(storagePath, "utf8"));
		if (storage.cookies) await browser.addCookies(storage.cookies);
		page.on("domcontentloaded", () => {
			void page.evaluate((savedStorage) => {
				for (const [key, value] of Object.entries(savedStorage.localStorage || {})) {
					window.localStorage.setItem(key, value as string);
				}
				for (const [key, value] of Object.entries(savedStorage.sessionStorage || {})) {
					window.sessionStorage.setItem(key, value as string);
				}
			}, storage);
		});
	} catch (error) {
		console.warn(`[proton] ignoring unreadable saved browser storage: ${error instanceof Error ? error.message : String(error)}`);
	}
}

async function persistBrowserStorage(page: Page, browser: Awaited<ReturnType<typeof chromium.launchPersistentContext>>): Promise<void> {
	const serializedStorage = await page.evaluate(() => JSON.stringify({ localStorage, sessionStorage }));
	const storage = JSON.parse(serializedStorage);
	storage.cookies = await browser.cookies();
	writeFileSync(storagePath, JSON.stringify(storage), "utf8");
}

async function login(): Promise<Page> {
	console.log("[proton] starting account browser");
	const browser = await chromium.launchPersistentContext(userDataDirectory, {
		args: [
			"--no-sandbox",
			"--disable-setuid-sandbox",
			"--disable-dev-shm-usage",
			"--disable-accelerated-2d-canvas",
			"--no-first-run",
			"--no-zygote",
			"--disable-gpu",
			"--disable-software-rasterizer",
		],
		headless: true,
		channel: "chrome",
	});
	const page = await browser.newPage();
	await restoreBrowserStorage(page, browser);

	const response = await page.goto("https://account.protonvpn.com/account-password", { waitUntil: "domcontentloaded" });
	console.log(`[proton] account page loaded: ${response?.status() || "no response"}`);
	const accountOrUsername = page.locator("section#account, #username");
	await accountOrUsername.waitFor({ state: "attached", timeout: 30_000 });
	const pageId = await accountOrUsername.evaluate((element) => element.id);
	if (pageId === "account") return page;

	const credentials = accountCredentials();
	console.log("[proton] logging in to the account page");
	await page.fill("#username", credentials.username);
	await page.click("button[type=submit]");
	await page.locator("#password").waitFor({ state: "attached", timeout: 10_000 });
	await page.fill("#password", credentials.password);
	await page.click("button[type=submit]");
	await page.locator("section#account").waitFor({ state: "attached", timeout: 30_000 });
	await persistBrowserStorage(page, browser);
	console.log("[proton] account login completed");
	return page;
}

let pagePromise: Promise<Page> | undefined;

function accountPage(): Promise<Page> {
	pagePromise ??= login().catch((error) => {
		pagePromise = undefined;
		throw error;
	});
	return pagePromise;
}

async function resetCredentialsWithPage(page: Page, retryAfterPasswordPrompt: boolean): Promise<OpenVpnCredentials> {
	const openVpnSection = page.locator("section#openvpn");
	await openVpnSection.waitFor({ state: "attached", timeout: 30_000 });
	await openVpnSection.scrollIntoViewIfNeeded();
	const resetButton = openVpnSection.locator("button.button.button-medium.button-solid-norm");
	await resetButton.waitFor({ state: "attached", timeout: 10_000 });

	const responsePromise = page.waitForResponse((response) => response.url() === resetEndpoint, { timeout: 30_000 });
	console.log("[proton] resetting OpenVPN credentials");
	await resetButton.click();
	const response = await responsePromise;
	const body = await response.json();
	if (!body?.Error) {
		const username = body?.VPNSettings?.Name;
		const password = body?.VPNSettings?.Password;
		if (typeof username !== "string" || !username || typeof password !== "string" || !password) {
			throw new Error("Proton returned an invalid OpenVPN credential response");
		}
		return { username, password };
	}

	if (!retryAfterPasswordPrompt) {
		throw new Error(`Proton rejected the OpenVPN credential reset: ${String(body.Error)}`);
	}
	const passwordInput = page.locator("#password");
	if ((await passwordInput.count()) === 0) {
		throw new Error(`Proton rejected the OpenVPN credential reset: ${String(body.Error)}`);
	}
	await passwordInput.fill(accountCredentials().password);
	await page.click('button[type=submit][form="auth-form"]');
	await sleep(3000);
	return resetCredentialsWithPage(page, false);
}

let credentialReset: Promise<OpenVpnCredentials> | undefined;

/**
 * Proton's OpenVPN password is account-wide.  Sharing one in-flight reset is
 * essential when several active OpenVPN tunnels see AUTH_FAILED together:
 * resetting it per tunnel repeatedly invalidates the credential every other
 * tunnel is trying to use.
 */
export function resetCredentials(): Promise<OpenVpnCredentials> {
	if (!credentialReset) {
		credentialReset = accountPage().then((page) => resetCredentialsWithPage(page, true)).finally(() => {
			credentialReset = undefined;
		});
	}
	return credentialReset;
}
