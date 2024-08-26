import * as types from '$lib/type';
import { setting } from '$lib/index.server';

const origin = {
	client_server: setting.SNS_ORIGIN ?? 'http://localhost:3001',
	auth_server: setting.SNS_ORIGIN
};

const authServer = {
	tokenEndpoint: origin.auth_server + '/token'
};

const client = {
	client_id: setting.SNS_CLIENT_ID,
	client_secret: setting.SNS_SECRET_ID,
	redirect_uris: [origin.client_server + '/callback'],
	scope: 'read write delete'
};

export async function tokenRequest() {
	if (!client.client_id || !client.client_secret) {
		return null;
	}

	const form_data = new URLSearchParams({
		grant_type: 'client_credentials',
		scope: client.scope
	}).toString();

	const headers = {
		Origin: setting.ORIGIN,
		'Content-Type': 'application/x-www-form-urlencoded',
		Authorization:
			'Basic ' +
			Buffer.from(
				encodeURIComponent(client.client_id) + ':' + encodeURIComponent(client.client_secret)
			).toString('base64')
	};
	let token_response:Response;
	try{
		token_response = await fetch(authServer.tokenEndpoint, {
			method: 'POST',
			headers: headers,
			body: form_data
		});
	} catch {
		if (authServer.tokenEndpoint.startsWith("http://")){
			authServer.tokenEndpoint=authServer.tokenEndpoint.replace("http://", "https://")
		} else {
			authServer.tokenEndpoint=authServer.tokenEndpoint.replace("https://", "http://")
		}
		token_response = await fetch(authServer.tokenEndpoint, {
			method: 'POST',
			headers: headers,
			body: form_data
		});
	}
	

	if (token_response.ok) {
		const body: types.TokenResponse = await token_response.json();
		const token = body.access_token;
		return token;
	} else {
		console.error('Error: Failed to fetch token', token_response.status, token_response.statusText);
		return null;
	}
}
