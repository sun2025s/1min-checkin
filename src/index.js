const core = require("@actions/core");
const crypto = require("node:crypto");
const OTPAuth = require("otpauth");
const { notify } = require("./notifier.js");

const REQUEST_TIMEOUT_MS = 10000;
const CHECKIN_SETTLE_MS = 3000;
const ACCOUNT_INTERVAL_MS = 8000; // 账号之间间隔 8 秒
const USER_AGENT =
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36";

class OneMinAutoCheckin {
	constructor(account) {
		this.email = account.email;
		this.password = account.password;
		this.totpSecret = this.validateTotpSecret(
			account.totp || account.totp_secret,
		);
		this.deviceId = this.generateDeviceId();
	}

	validateTotpSecret(secret) {
		return secret && secret !== "null" && String(secret).trim() !== ""
			? secret
			: null;
	}

	generateDeviceId() {
		const randomHex = (length) =>
			crypto.randomBytes(length).toString("hex").slice(0, length);
		return `$device:${randomHex(16)}-${randomHex(15)}-${randomHex(8)}-${randomHex(6)}-${randomHex(16)}`;
	}

	buildHeaders(authToken) {
		return {
			Host: "api.1min.ai",
			"Content-Type": "application/json",
			"X-Auth-Token": authToken ? `Bearer ${authToken}` : "Bearer",
			"Mp-Identity": this.deviceId,
			"User-Agent": USER_AGENT,
			Accept: "application/json, text/plain, */*",
			Origin: "https://app.1min.ai",
			Referer: "https://app.1min.ai/",
		};
	}

	async fetchWithTimeout(url, options = {}) {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
		try {
			return await fetch(url, { ...options, signal: controller.signal });
		} finally {
			clearTimeout(timeoutId);
		}
	}

	maskEmail(email) {
		const atIdx = email.indexOf("@");
		if (atIdx <= 0) return "***";
		return `${email.substring(0, Math.min(3, atIdx))}***${email.substring(atIdx)}`;
	}

	async login() {
		core.info(`[${this.maskEmail(this.email)}] 开始登录...`);

		const body = JSON.stringify({
			email: this.email,
			password: this.password,
		});

		const response = await this.fetchWithTimeout(
			"https://api.1min.ai/auth/login",
			{
				method: "POST",
				headers: this.buildHeaders(),
				body,
			},
		);

		const data = await response.json();

		if (response.status === 200 && data.user) {
			if (data.user.mfaRequired) {
				if (!this.totpSecret) {
					throw new Error("需要 TOTP 但未提供密钥");
				}
				return await this.performMFAVerification(data.user.token);
			}
			return await this.displayCreditInfo(data);
		}

		let errorMsg = data.message || "登录失败";
		if (response.status === 401) errorMsg = "邮箱或密码错误";
		if (response.status === 429) errorMsg = "请求过于频繁";
		throw new Error(errorMsg);
	}

	async performMFAVerification(tempToken) {
		const totp = new OTPAuth.TOTP({
			secret: this.totpSecret,
			digits: 6,
			period: 30,
			algorithm: "SHA1",
		});
		const totpCode = totp.generate();

		const response = await this.fetchWithTimeout(
			"https://api.1min.ai/auth/mfa/verify",
			{
				method: "POST",
				headers: this.buildHeaders(),
				body: JSON.stringify({ code: totpCode, token: tempToken }),
			},
		);

		const data = await response.json();
		if (response.status === 200) {
			return await this.displayCreditInfo(data);
		}
		throw new Error(data.message || `TOTP 验证失败 HTTP ${response.status}`);
	}

	async displayCreditInfo(responseData) {
		const user = responseData.user;
		if (!user?.teams || user.teams.length === 0) {
			core.info(`[${this.maskEmail(this.email)}] 登录成功（无法获取积分信息）`);
			return {
				userName: this.maskEmail(this.email),
				finalCredit: 0,
				creditDiff: 0,
			};
		}

		const authToken = responseData.token || responseData.user?.token;
		const userUuid = user.uuid;

		const targetTeam =
			user.teams.find((t) => t.team?.subscription?.userId === userUuid) ||
			user.teams[0];

		const teamId = targetTeam.teamId || targetTeam.team?.uuid;
		const userName = targetTeam.userName || user.email?.split("@")[0] || "User";
		const usedCredit = targetTeam.usedCredit || 0;
		const initialCredit = targetTeam.team?.credit || 0;

		if (!teamId || !authToken) {
			return {
				userName,
				finalCredit: initialCredit,
				creditDiff: 0,
				availablePercent: this.calculatePercent(initialCredit, usedCredit),
			};
		}

		return await this.fetchLatestCredit(
			teamId,
			authToken,
			userName,
			usedCredit,
			initialCredit,
		);
	}

	async fetchLatestCredit(
		teamId,
		authToken,
		userName,
		usedCredit,
		initialCredit = 0,
	) {
		const headers = this.buildHeaders(authToken);

		const currentCredit =
			initialCredit > 0
				? initialCredit
				: await this.getCredits(teamId, headers);

		// 触发签到的关键步骤
		await this.checkUnreadNotifications(headers);

		await new Promise((r) => setTimeout(r, CHECKIN_SETTLE_MS));
		const finalCredit = await this.getCredits(teamId, headers);

		const creditDiff = finalCredit - currentCredit;
		const totalCredit = finalCredit + usedCredit;
		const availablePercent =
			totalCredit > 0 ? ((finalCredit / totalCredit) * 100).toFixed(1) : "0";

		if (creditDiff > 0) {
			core.info(
				`[${this.maskEmail(this.email)}] 成功领取 +${creditDiff.toLocaleString()} 积分 | 余额 ${finalCredit.toLocaleString()}`,
			);
		} else {
			core.info(
				`[${this.maskEmail(this.email)}] 今日已签到或无奖励 | 余额 ${finalCredit.toLocaleString()}`,
			);
		}

		return { userName, finalCredit, creditDiff, availablePercent };
	}

	async getCredits(teamId, headers) {
		try {
			const response = await this.fetchWithTimeout(
				`https://api.1min.ai/teams/${teamId}/credits`,
				{ headers },
			);
			if (response.status === 200) {
				const data = await response.json();
				return data.credit || 0;
			}
		} catch (e) {}
		return 0;
	}

	async checkUnreadNotifications(headers) {
		try {
			await this.fetchWithTimeout("https://api.1min.ai/notifications/unread", {
				headers,
			});
		} catch (e) {}
	}

	calculatePercent(remaining, used) {
		const total = remaining + used;
		return total > 0 ? ((remaining / total) * 100).toFixed(1) : "0";
	}

	async run() {
		try {
			const result = await this.login();
			return { success: true, email: this.maskEmail(this.email), ...result };
		} catch (error) {
			core.error(`[${this.maskEmail(this.email)}] 失败: ${error.message}`);
			return {
				success: false,
				email: this.maskEmail(this.email),
				error: error.message,
			};
		}
	}
}

async function main() {
	core.info("===== 1min.ai 多账号自动签到开始 =====");
	core.info(`执行时间: ${new Date().toISOString()}`);

	// 优先读取 ACCOUNTS_JSON，兼容旧的单账号方式
	let accounts = [];
	const accountsJson =
		process.env.ACCOUNTS_JSON || core.getInput("accounts_json");

	if (accountsJson) {
		try {
			accounts = JSON.parse(accountsJson);
			if (!Array.isArray(accounts)) throw new Error("ACCOUNTS_JSON 必须是数组");
		} catch (e) {
			core.setFailed(`解析 ACCOUNTS_JSON 失败: ${e.message}`);
			process.exit(1);
		}
	} else {
		// 兼容原单账号配置
		const email = process.env.EMAIL || core.getInput("email");
		const password = process.env.PASSWORD || core.getInput("password");
		const totp = process.env.TOTP_SECRET || core.getInput("totp_secret");
		if (email && password) {
			accounts = [{ email, password, totp }];
		}
	}

	if (accounts.length === 0) {
		core.setFailed("未配置任何账号，请设置 ACCOUNTS_JSON 或 EMAIL/PASSWORD");
		process.exit(1);
	}

	core.info(`共检测到 ${accounts.length} 个账号`);

	const results = [];
	for (let i = 0; i < accounts.length; i++) {
		const acc = accounts[i];
		if (!acc.email || !acc.password) {
			core.warning(`第 ${i + 1} 个账号缺少 email 或 password，跳过`);
			continue;
		}

		core.info(`\n----- 处理第 ${i + 1}/${accounts.length} 个账号 -----`);
		const checker = new OneMinAutoCheckin(acc);
		const result = await checker.run();
		results.push(result);

		// 账号之间间隔
		if (i < accounts.length - 1) {
			await new Promise((r) => setTimeout(r, ACCOUNT_INTERVAL_MS));
		}
	}

	// 汇总结果
	const successCount = results.filter((r) => r.success).length;
	core.info(`\n===== 全部完成 =====`);
	core.info(`成功: ${successCount}/${results.length}`);

	// 发送汇总通知（如果配置了 Telegram）
	try {
		const summary = {
			success: successCount > 0,
			results,
			message: `多账号签到完成：成功 ${successCount}/${results.length}`,
		};
		await notify(summary);
	} catch (e) {
		core.warning(`通知发送失败: ${e.message}`);
	}

	if (successCount === 0) {
		core.setFailed("所有账号均失败");
		process.exit(1);
	}
}

if (require.main === module) {
	main();
}

module.exports = OneMinAutoCheckin;
