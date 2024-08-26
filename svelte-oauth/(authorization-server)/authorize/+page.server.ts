import type { PageServerLoad } from './$types';
import type { Actions } from './$types';
import { fail, redirect } from '@sveltejs/kit';
import { authorizeRequestProcess, approveResponse } from '$lib/authorization.server';
import { tokenCookieOptions, tokenExpireHours, check_auth } from '$lib/index.server';
import { zxcvbnOptions } from '@zxcvbn-ts/core';
import { zxcvbnOption } from '$lib';
import * as types from '$lib/type';
import { db } from '$lib/db/db.server';
import { Token, User } from '$lib/db/schemas';
import { eq } from 'drizzle-orm';
import bcrypt from 'bcryptjs';
import { tokenRequest } from '$lib/client.server';

zxcvbnOptions.setOptions(zxcvbnOption);

export const load: PageServerLoad = async ({ url, cookies }) => {
	const query_params: types.UrlOption = {
		response_type: url.searchParams.get('response_type') || '',
		scope: url.searchParams.get('scope') || '',
		client_id: url.searchParams.get('client_id') || '',
		redirect_uri: url.searchParams.get('redirect_uri') || '',
		state: url.searchParams.get('state') || ''
	};

	let authorize_embedded_data = authorizeRequestProcess(query_params);
	if (!authorize_embedded_data) {
		return fail(400, { error: 'Bad request' });
	}

	const token = cookies.get('token');
	const auth = await check_auth(token);

	if (auth.authed) {
		const name = auth.user?.name;
		const user_id = auth.user?.id;
		if (!name || !user_id) {
			return fail(400, { name, missing: true });
		}
		const redirect_url = approveResponse(authorize_embedded_data, user_id!, 'true');
		if (!redirect_url) {
			return fail(500, { error: 'Nothing request' });
		}
		redirect(301, redirect_url);
	}

	return { authorize_embedded_data };
};

export const actions = {
	default: async ({ request, cookies }) => {
		const data = await request.formData();
		const request_id = data.get('request_id')?.toString() || '';
		const scope = getScopesFromForm(data);
		const approve = data.get('approve')?.toString() || '';
		const name = data.get('name')?.toString();
		const password = data.get('password');

		if (!name || !password) {
			return fail(400, { name, missing: true });
		}
		const user = await db.query.User.findFirst({
			where: eq(User.name, name.toString())
		});
		if (!user) {
			return fail(400, { name, incorrect: true });
		}
		if (!(await bcrypt.compare(password.toString(), user.password))) {
			return fail(400, { name, incorrect: true });
		}

		const token = await tokenRequest();

		if (!token) {
			return fail(500, { error: 'Internal Server Error' });
		}
		const expired_in = new Date();
		expired_in.setHours(expired_in.getHours() + tokenExpireHours);
		const db_info = await db
			.insert(Token)
			.values({ token: token, user_id: user.id, expired_in: expired_in })
			.returning();

		const user_id = db_info[0]?.user_id;
		cookies.set('token', token, tokenCookieOptions);

		let authorize_embedded_data: types.AuthorizeEmbeddedData = { request_id, scope, client_name:"dummy" };
		const redirect_url = approveResponse(authorize_embedded_data, user_id!, approve);
		if (!redirect_url) {
			return fail(500, { error: 'Nothing request' });
		}
		redirect(301, redirect_url);
	}
} satisfies Actions;

function getScopesFromForm(form_data: FormData) {
	let scope: string[] = [];
	for (const entry of form_data.entries()) {
		if (entry[0].startsWith('scope_') && entry[1] === 'on') {
			scope.push(entry[0].replace('scope_', ''));
		}
	}
	return scope.join(' ');
}
