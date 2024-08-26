<script lang="ts">
	import { onMount } from 'svelte';
	import Label from 'flowbite-svelte/Label.svelte';
	import Input from 'flowbite-svelte/Input.svelte';
	import Button from 'flowbite-svelte/Button.svelte';
	import Alert from 'flowbite-svelte/Alert.svelte';
	import Heading from 'flowbite-svelte/Heading.svelte';
	import type { PageData, ActionData } from './$types';
	import { enhance } from '$app/forms';

	export let data: PageData;
	export let form: ActionData;

	const scopeDescriptions: { [scope: string]: string } = {
		read: 'リソースの読み取り権限',
		write: 'リソースの書き込み権限',
		delete: 'リソースの削除権限'
	};
</script>

<Heading>SSOでログイン</Heading>

<form method="POST" use:enhance class="space-y-4">
	<input type="hidden" name="request_id" value={data.authorize_embedded_data?.request_id} />
	{#if form?.missing ?? false}
		<Alert>入力が不足しています。</Alert>
	{/if}
	{#if form?.incorrect ?? false}
		<Alert>入力に誤りがあります。</Alert>
	{/if}
	{#if form?.error}
		<Alert>エラーが発生しました: {form.error}</Alert>
	{/if}
	<div>
		<Label for="name">ユーザ名</Label>
		<Input type="text" id="name" name="name" required />
	</div>
	<div>
		<Label for="password">パスワード</Label>
		<Input type="password" id="password" name="password" required />
	</div>
	{#if data.authorize_embedded_data?.scope}
		<p class="mt-4">{data.authorize_embedded_data.client_name}がリソースへのアクセスをリクエストしています</p>
		<p class="mb-2">{data.authorize_embedded_data.client_name}に以下を許可します:</p>
		<ul class="list-inside list-disc">
			{#each data.authorize_embedded_data.scope?.split(' ') as s}
				{#if scopeDescriptions[s]}
					<li class="mt-2">
						<input type="hidden" name="scope_{s}" id="scope_{s}" value="on" />
						<span>{scopeDescriptions[s]}</span>
					</li>
				{:else}
					<input type="hidden" name="scope_{s}" id="scope_{s}" value="on" />
				{/if}
			{/each}
		</ul>
	{/if}

	<Button type="submit" name="approve" value="true">次へ</Button>
	<Button type="submit" name="approve" value="false">キャンセル</Button>
</form>
<Button type="button" on:click={() => (location.href = './signup')}>新規登録</Button>
