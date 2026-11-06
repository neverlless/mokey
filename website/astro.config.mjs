import starlight from '@astrojs/starlight';
import { satteri } from '@astrojs/markdown-satteri';
import mermaid from 'astro-mermaid';
import { defineConfig } from 'astro/config';
import { githubAlerts, mdLinks } from './src/markdown.mjs';

const base = '/mokey';

export default defineConfig({
	site: 'https://neverlless.github.io',
	base,
	trailingSlash: 'always',
	markdown: {
		processor: satteri({ mdastPlugins: [githubAlerts(), mdLinks(base)] }),
	},
	integrations: [
		mermaid({ autoTheme: true, enableLog: false, mermaidConfig: { fontFamily: 'IBM Plex Sans, sans-serif', flowchart: { useMaxWidth: false } } }),
		starlight({
			title: 'mokey',
			description: 'Self-service account management portal for FreeIPA / Red Hat IdM',
			logo: { src: '../docs/assets/mokey-tile.svg' },
			favicon: '/favicon.svg',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/neverlless/mokey' }],
			editLink: { baseUrl: 'https://github.com/neverlless/mokey/edit/main/docs/' },
			markdown: { processedDirs: ['../docs'] },
			customCss: [
				'@fontsource/ibm-plex-sans/400.css',
				'@fontsource/ibm-plex-sans/500.css',
				'@fontsource/ibm-plex-sans/600.css',
				'@fontsource/ibm-plex-mono/400.css',
				'./src/styles/brand.css',
			],
			sidebar: [
				{ label: 'Home', link: '/' },
				{ label: 'Install', slug: 'install' },
				{
					label: 'Guides',
					items: [
						{ label: 'Self-service password reset', slug: 'guides/password-reset' },
						{ label: 'User signup and approval', slug: 'guides/signup' },
						{ label: 'OTP tokens', slug: 'guides/otp' },
						{ label: 'Passkeys', slug: 'guides/passkeys' },
						{ label: 'OIDC / SSO with Ory Hydra', slug: 'guides/oidc-hydra' },
						{ label: 'Group self-service', slug: 'guides/groups' },
						{ label: 'Access page (HBAC and sudo)', slug: 'guides/access' },
						{ label: 'App catalog', slug: 'guides/app-catalog' },
						{ label: 'Webhooks and JSON API', slug: 'guides/webhooks-api' },
						{ label: 'Admin helpdesk view', slug: 'guides/helpdesk' },
					],
				},
				{
					label: 'Companion mode',
					items: [
						{ label: 'Next to any OIDC provider', slug: 'companion/oidc-provider' },
						{ label: 'Next to Keycloak (SAML broker)', slug: 'keycloak' },
					],
				},
				{ label: 'Comparisons', slug: 'comparison' },
				{
					label: 'Reference',
					items: [
						{ label: 'Configuration', slug: 'configuration' },
						{ label: 'Hydra v1 to v2 migration', slug: 'hydra-v2-migration' },
					],
				},
				{
					label: 'Project',
					items: [
						{ label: 'Roadmap', slug: 'ROADMAP' },
						{ label: 'Security audit (v1.6)', slug: 'security-audit-v1.6' },
					],
				},
			],
		}),
	],
});
