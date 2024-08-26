import { db } from '$lib/db/db.server';
import { Token } from '$lib/db/schemas';
import { randomString, buildUrl, tokenExpireHours } from '$lib/index.server';
import { json } from '@sveltejs/kit';
import { setting } from '$lib/index.server';
import * as types from '$lib/type';

const origin = {
	tws_server: setting.TWS_SERVER_ORIGIN,
	sns_server: setting.SNS_ORIGIN,
	auth_server: setting.SNS_ORIGIN
};

const clients = [
	{
		client_name: "Tmitter",
		client_id: setting.SNS_CLIENT_ID,
		client_secret: setting.SNS_SECRET_ID,
		redirect_uris: [origin.sns_server + '/callback'],
		scope: 'read write delete'
	},
	{
		client_name: "TMCIT Web Services",
		client_id: setting.TWS_CLIENT_ID,
		client_secret: setting.TWS_SECRET_ID,
		redirect_uris: [origin.tws_server + '/api/v1/oauth/callback'],
		scope: 'read write delete'
	}
];

const requests: { [reqid: string]: types.UrlOption } = {};
const codes: { [code: string]: types.DataWithCode } = {};

export function getClient(client_id: string) {
	const client = clients.find((clients) => clients.client_id == client_id);
	return client;
}

export function authorizeRequestProcess(query_params: types.UrlOption) {
	const client = getClient(query_params.client_id);

	if (!client) {
		console.error('Error: Unknown client %s', query_params.client_id);
		return null;
	} else if (!client.redirect_uris.includes(query_params.redirect_uri)) {
		console.error(
			'Error: Mismatched redirect URI, expected %s got %s',
			client.redirect_uris,
			query_params.redirect_uri
		);
		return null;
	}

	const request_scope: string[] = query_params.scope ? query_params.scope.split(' ') : [];
	const client_scope: string[] = client.scope ? client.scope.split(' ') : [];

	if (request_scope.some((scope) => !client_scope.includes(scope))) {
		console.error('Error: Invalid scope %s', request_scope);
		return null;
	}

	const request_id = randomString(8);
	requests[request_id] = query_params;

	const request: types.AuthorizeEmbeddedData = {
		request_id: request_id,
		scope: request_scope.join(' '),
		client_name: client.client_name,
	};
	return request;
}

export function approveResponse(
	authorize_embedded_data: types.AuthorizeEmbeddedData,
	user_id: string,
	approve: string
) {
	const requestId = authorize_embedded_data.request_id;
	const request = requests[requestId];
	delete requests[requestId];

	if (!request) {
		console.error('Error: Nothing request');
		return null;
	}

	if (approve == 'true') {
		if (request.response_type == 'code') {
			const code = randomString(8);
			const approve_scope = authorize_embedded_data.scope;
			const client = getClient(request.client_id);
			const client_scope = client?.scope ? client.scope.split(' ') : '';

			if (
				approve_scope &&
				client_scope &&
				approve_scope.split(' ').some((scope) => !client_scope.includes(scope))
			) {
				console.error('Error: Invalid scope %s', approve_scope);
				return request.redirect_uri + '?error=' + 'Invalid scope' + approve_scope;
			}

			codes[code] = { raw_request: request, scope: approve_scope, user_id: user_id };

			return buildUrl(request.redirect_uri, {
				code: code,
				state: request.state
			});
		} else {
			console.error('Error: Unsupported response type');
			return request.redirect_uri + '?error=' + 'unsupported response type';
		}
	} else {
		console.error('Error: OAuth denied');
		return request.redirect_uri + '?error=' + 'oauth denied';
	}
}

export async function tokenResponse({ authorization_header, body }: types.TokenRequest) {
	if (!authorization_header) {
		return json({ error: 'Unauthorized' }, { status: 401 });
	}
	const client_credentials = Buffer.from(authorization_header.slice('basic '.length), 'base64')
		.toString()
		.split(':');
	const client_id = decodeURIComponent(client_credentials[0]);
	const client_secret = decodeURIComponent(client_credentials[1]);

	const client = getClient(client_id);

	if (!client || client.client_secret != client_secret) {
		return json({ error: 'Bad Request' }, { status: 400 });
	}

	if (body.grant_type == 'authorization_code') {
		const code = codes[body.code];

		if (code) {
			delete codes[body.code];
			if (code.raw_request.client_id == client_id) {
				const access_token = randomString(32);

				const expired_in = new Date();
				expired_in.setHours(expired_in.getHours() + tokenExpireHours);
				await db
					.insert(Token)
					.values({
						token: access_token,
						user_id: code.user_id,
						expired_in: expired_in,
						outer: true
					});

				const token_response: types.TokenResponse = {
					access_token: access_token,
					token_type: 'Bearer',
					scope: code.raw_request.scope,
					user_id: code.user_id
				};
				return json(token_response, { status: 200 });
			}
		}
	} else if (body.grant_type == 'client_credentials') {
		const request_scope: string[] = body.scope ? body.scope.split(' ') : [];
		const client_scope: string[] = client.scope ? client.scope.split(' ') : [];

		if (request_scope.some((scope) => !client_scope.includes(scope))) {
			console.error('Error: Invalid scope %s', request_scope);
			return json({ error: 'Bad request' }, { status: 400 });
		}

		const access_token = randomString(32);

		const token_response: types.TokenResponse = {
			access_token: access_token,
			token_type: 'Bearer',
			scope: body.scope
		};
		return json(token_response, { status: 200 });
	}
	return json({ error: 'Bad request' }, { status: 400 });
}
