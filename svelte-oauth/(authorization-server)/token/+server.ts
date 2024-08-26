import { json } from '@sveltejs/kit';
import { tokenResponse } from '$lib/authorization.server';

export async function POST({ request }: any) {
	const authorization_header = request.headers.get('authorization');
	const formdata = await request.formData();
	const grant_type = formdata.get('grant_type') || '';
	let body;
	if (grant_type === 'authorization_code') {
		body = {
			grant_type: formdata.get('grant_type') || '',
			code: formdata.get('code') || '',
			redirect_uri: formdata.get('redirect_uri') || ''
		};
	} else if (grant_type === 'client_credentials') {
		body = {
			grant_type: formdata.get('grant_type') || '',
			scope: formdata.get('scope') || ''
		};
	} else {
		return json({ error: 'Bad Request' }, { status: 400 });
	}

	let token_response = await tokenResponse({ authorization_header, body });

	return token_response;
}
