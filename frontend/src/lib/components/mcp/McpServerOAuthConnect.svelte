<script lang="ts">
	import { McpOauthService, ResourceService, type DiscoverMcpOauthResponse } from '$lib/gen'
	import { Button } from '$lib/components/common'
	import Label from '$lib/components/Label.svelte'
	import { sendUserToast } from '$lib/toast'
	import { upsertSecretVariable } from './secretVariable'
	import { onDestroy, onMount } from 'svelte'

	interface Props {
		/** Carries the workspace the connection was created in: a popup outlives a
		 * workspace switch on the page behind it. */
		onConnected: (workspace: string, path: string) => void
		/** The server to sign in to. Discovery runs against it on mount. */
		server: { name: string; url: string }
		/** Where the resource and its token variable land. */
		path: string
		/** Reports what discovery found, so the caller can offer the right fallback. */
		onDiscovered?: (supportsOAuth: boolean) => void
		/** Required: a caller that forgot it would create the connection in whichever
		 * workspace the ui happens to be showing. */
		workspace: string
	}

	let { onConnected, server, path, onDiscovered, workspace }: Props = $props()

	let serverUrl = $derived(server.url)
	let resourceName = $derived(server.name.toLowerCase().replace(/[^a-z0-9]/g, '_'))
	let discoveryResult = $state<DiscoverMcpOauthResponse | null>(null)
	let selectedScopes = $state<string[]>([])
	let status = $state<'idle' | 'discovering' | 'discovered' | 'connecting'>('idle')
	let error = $state<string | null>(null)
	let noOAuth = $state(false)
	let pending:
		| { workspace: string; path: string; serverUrl: string; name: string; scopes: string[] }
		| undefined = undefined
	let popup: Window | null = null
	let popupPoll: ReturnType<typeof setInterval> | undefined
	let destroyed = false

	async function discoverOAuth() {
		status = 'discovering'
		error = null
		try {
			discoveryResult = await McpOauthService.discoverMcpOauth({
				requestBody: { mcp_server_url: serverUrl }
			})
			// The caller keys this component on the url, so editing it replaces this
			// instance while its request is still in flight. Reporting the answer then
			// would describe the previous server: a slow failure would take the new
			// connector down with it.
			if (destroyed) return
			selectedScopes = discoveryResult?.scopes_supported ?? []
			noOAuth = false
			status = 'discovered'
			onDiscovered?.(true)
		} catch (e) {
			if (destroyed) return
			console.error('Error discovering OAuth settings', e)
			noOAuth = true
			status = 'idle'
			onDiscovered?.(false)
		}
	}

	function startOAuth() {
		if (status !== 'discovered' || pending) return
		error = null
		// Fixed when the popup opens: the page behind it can move on, and the
		// callback must still land where the user aimed it.
		pending = { workspace, path, serverUrl, name: resourceName, scopes: [...selectedScopes] }
		const url = new URL(`/api/mcp/oauth/start`, window.location.origin)
		url.searchParams.set('mcp_server_url', serverUrl)
		url.searchParams.set('scopes', selectedScopes.join(','))

		popup = window.open(url.toString(), '_blank', 'popup=true')
		if (!popup) {
			pending = undefined
			error = 'Popup blocked. Please allow popups for this site.'
			return
		}

		window.addEventListener('message', handleOAuthMessage)
		status = 'connecting'
		popupPoll = setInterval(() => {
			if (popup?.closed) {
				cleanup()
				pending = undefined
				popup = null
				status = 'discovered'
				error = 'Authentication window closed. Connect again to retry.'
			}
		}, 500)
	}

	function handleOAuthMessage(event: MessageEvent) {
		if (event.origin !== window.location.origin) return

		// Every connector on the page hears this, so one only takes the completion
		// for the window it opened — both ways: another connector's completion must
		// not be taken as ours, nor its failure tear this one down mid-flight.
		if (event.source !== popup) return
		if (!pending || !event.data || typeof event.data !== 'object') return
		if (event.data.type === 'MCP_CONNECTED') {
			if (event.data.mcp_server_url !== pending?.serverUrl) return
			cleanup()
			createMcpResource(event.data)
		} else if (event.data.type === 'MCP_ERROR') {
			cleanup()
			pending = undefined
			popup = null
			error = event.data.error
			status = 'discovered'
		}
	}

	function cleanup() {
		window.removeEventListener('message', handleOAuthMessage)
		clearInterval(popupPoll)
		popupPoll = undefined
	}

	async function createMcpResource(data: {
		access_token: string
		refresh_token?: string
		expires_in?: number
		scope?: string
		mcp_server_url: string
	}) {
		const target = pending
		if (!target) return
		pending = undefined
		popup = null
		const { workspace, path } = target
		try {
			await upsertSecretVariable({
				workspace,
				path,
				value: data.access_token,
				resourcePath: path,
				isOauth: true,
				account: data.refresh_token
					? {
							refresh_token: data.refresh_token,
							expires_in: data.expires_in ?? 3600,
							client: 'mcp',
							scopes: data.scope?.split(/\s+/).filter(Boolean) ?? target.scopes,
							mcp_server_url: data.mcp_server_url
						}
					: undefined
			})

			await ResourceService.createResource({
				workspace,
				requestBody: {
					resource_type: 'mcp',
					path: path,
					value: {
						name: target.name,
						url: data.mcp_server_url,
						token: `$var:${path}`
					},
					description: `MCP server connected via OAuth`
				}
			})

			sendUserToast('Connected to MCP server')
			onConnected(workspace, path)
		} catch (e: any) {
			error = e.body?.message || e.message || 'Failed to create resource'
			status = 'discovered'
		}
	}

	/** The caller renders the action, below its own path picker. */
	export function start() {
		startOAuth()
	}
	export function canStart(): boolean {
		return status === 'discovered'
	}
	export function isConnecting(): boolean {
		return status === 'connecting'
	}

	onMount(discoverOAuth)

	onDestroy(() => {
		destroyed = true
		cleanup()
	})
</script>

<div class="flex flex-col gap-4">
	{#if status === 'idle'}
		{#if noOAuth}
			<div class="text-2xs text-secondary">{server.name} did not advertise OAuth support.</div>
		{/if}
		<Button
			unifiedSize="2xs"
			variant="subtle"
			wrapperClasses="self-start"
			onClick={discoverOAuth}
			disabled={!serverUrl}
		>
			{noOAuth ? 'Check again' : 'Check for OAuth support'}
		</Button>
	{:else if status === 'discovering'}
		<div class="text-xs text-secondary">Checking what {server.name} supports...</div>
	{:else if status === 'discovered' && discoveryResult}
		{#if discoveryResult.scopes_supported && discoveryResult.scopes_supported.length > 0}
			<Label label="OAuth scopes">
				<div class="flex flex-col flex-wrap gap-2">
					{#each discoveryResult.scopes_supported as scope (scope)}
						<label class="flex flex-row items-center gap-2 text-xs cursor-pointer">
							<input
								type="checkbox"
								checked={selectedScopes.includes(scope)}
								onchange={(e) => {
									const target = e.target as HTMLInputElement
									if (target.checked) {
										selectedScopes = [...selectedScopes, scope]
									} else {
										selectedScopes = selectedScopes.filter((s) => s !== scope)
									}
								}}
								class="!w-4 !h-4"
							/>
							{scope}
						</label>
					{/each}
				</div>
			</Label>
		{/if}
	{:else if status === 'connecting'}
		<div class="text-xs text-secondary">Complete authentication in the popup window.</div>
	{/if}

	{#if error}
		<div class="text-xs text-red-600 dark:text-red-400">{error}</div>
	{/if}
</div>
