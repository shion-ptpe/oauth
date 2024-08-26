// place files you want to import through the `$lib` alias in this folder.
import { eq } from 'drizzle-orm';
import { db } from './db/db.server';
import { Token, User } from './db/schemas';
import { randomBytes } from 'crypto';
import * as types from '$lib/type';
import { env } from '$env/dynamic/private';

export const saltRounds = 10;
export const tokenCookieOptions = { httpOnly: true, secure: true, path: '/' };
export const tokenExpireHours = 12;

export const check_auth = async (token: string | undefined, include_password: boolean = false) => {
	if (!token) {
		return { authed: false, user: undefined };
	}
	const token_db = await db.query.Token.findFirst({ where: eq(Token.token, token) });
	if (!token_db) {
		return { authed: false, user: undefined };
	} else if (token_db.expired_in <= new Date()) {
		return { authed: false, user: undefined };
	} else {
		const user = await db.query.User.findFirst({ where: eq(User.id, token_db.user_id) });
		if (!user) {
			return { authed: false, user: undefined };
		}
		if (!include_password) {
			user.password = '';
			user.otp_key = '';
			user.otp_recovery = [];
		}
		return { authed: true, user: user };
	}
};

// https://zenn.dev/sanbasan/articles/a5a3b459db2637
const defaultCharset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';

export const randomString = (
	length: number,
	{ charset = defaultCharset, byteRange = 256 } = {}
): string => {
	if (length <= 0 || length > byteRange) {
		throw new Error(`length must satisfy 0 < length <= ${byteRange}, but ${length}.`);
	}

	let result = '';

	while (result.length < length) {
		const bytes = randomBytes(length);

		for (const byte of bytes) {
			result += charset[byte % charset.length];
			if (result.length === length) break;
		}
	}

	return result;
};

export const buildUrl = (
	base: string,
	options: types.UrlOption | types.CodeAndState,
	hash: string | undefined = undefined
) => {
	const newUrl = new URL(base);

	Object.entries(options).forEach(([key, value]) => {
		newUrl.searchParams.set(key, String(value));
	});

	if (hash) {
		newUrl.hash = hash;
	}

	return newUrl.toString();
};

export const setting = {
	TWS_SERVER_ORIGIN: env.TWS_SERVER_ORIGIN || "http://localhost:8001",
	SNS_ORIGIN: env.SNS_ORIGIN || "http://localhost:3000",
	SNS_CLIENT_ID: env.SNS_CLIENT_ID || randomString(16),
	SNS_SECRET_ID: env.SNS_SECRET_ID,
	TWS_CLIENT_ID: env.TWS_CLIENT_ID || randomString(16),
	TWS_SECRET_ID: env.TWS_SECRET_ID,
	ORIGIN: env.ORIGIN || env.SNS_ORIGIN || "http://localhost:3000"
}
