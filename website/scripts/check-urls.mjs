// Run after `npm run build`: every MkDocs-era URL must still resolve, and every
// internal link (and #anchor) in the built pages must point at something real.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const dist = new URL('../dist/', import.meta.url).pathname;
const base = '/mokey';

const oldUrls = [
	'/', '/install/', '/comparison/', '/configuration/', '/keycloak/',
	'/hydra-v2-migration/', '/ROADMAP/', '/security-audit-v1.6/',
	'/companion/oidc-provider/',
	...['password-reset', 'signup', 'otp', 'passkeys', 'oidc-hydra', 'groups', 'access',
		'app-catalog', 'webhooks-api', 'helpdesk'].map((g) => `/guides/${g}/`),
	'/configuration/#users-without-a-freeipa-password',
	'/install/#try-it-the-demo',
];

const pages = new Map();
const idsOf = (path) => {
	if (!pages.has(path)) {
		const file = join(dist, path, path.endsWith('/') ? 'index.html' : '');
		pages.set(path, existsSync(file) ? new Set([...readFileSync(file, 'utf8').matchAll(/\sid="([^"]+)"/g)].map((m) => m[1])) : null);
	}
	return pages.get(path);
};

const errors = [];
const check = (url, from) => {
	const [path, hash] = url.split('#');
	const ids = idsOf(decodeURI(path));
	if (ids === null) errors.push(`${from}: ${url} does not exist`);
	else if (hash && path.endsWith('/') && !ids.has(decodeURIComponent(hash))) errors.push(`${from}: ${url} has no #${hash}`);
};

for (const url of oldUrls) check(url, 'old URL');

for (const file of readdirSync(dist, { recursive: true })) {
	if (!file.endsWith('.html')) continue;
	const from = '/' + file.replace(/index\.html$/, '');
	for (const [, href] of readFileSync(join(dist, file), 'utf8').matchAll(/<a [^>]*href="([^"]+)"/g)) {
		if (href.startsWith('#')) check(from + href, from);
		else if (href.startsWith(base + '/')) check(href.slice(base.length), from);
	}
}

if (errors.length) {
	console.error(errors.join('\n'));
	process.exit(1);
}
console.log(`URL check passed: ${oldUrls.length} old URLs, ${pages.size} pages/targets checked`);
