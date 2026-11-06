import { dirname, posix, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const docsDir = fileURLToPath(new URL('../../docs/', import.meta.url));
const alertTypes = { NOTE: 'note', TIP: 'tip', IMPORTANT: 'note', WARNING: 'caution', CAUTION: 'danger' };

/** GitHub alerts (`> [!NOTE]`) become Starlight asides, so docs/ reads the same on GitHub and on the site. */
export function githubAlerts() {
	return {
		name: 'github-alerts',
		blockquote(node) {
			const [first, ...rest] = node.children;
			const text = first?.type === 'paragraph' && first.children[0]?.type === 'text' ? first.children[0] : null;
			const match = text?.value.match(/^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*/);
			if (!match) return;
			const remainder = [{ ...text, value: text.value.slice(match[0].length) }, ...first.children.slice(1)];
			const lead = remainder.filter((n) => !(n.type === 'text' && n.value === '') && n.type !== 'break');
			const label = match[1][0] + match[1].slice(1).toLowerCase();
			return {
				type: 'containerDirective',
				name: alertTypes[match[1]],
				attributes: {},
				children: [
					{ type: 'paragraph', data: { directiveLabel: true }, children: [{ type: 'text', value: label }] },
					...(lead.length ? [{ type: 'paragraph', children: lead }] : []),
					...rest,
				],
			};
		},
	};
}

/** Rewrites relative `page.md#anchor` links to site URLs; GitHub needs the .md form. */
export function mdLinks(base) {
	return ({ fileURL }) => {
		if (!fileURL) return;
		const file = fileURLToPath(fileURL);
		if (!file.startsWith(docsDir)) return;
		return {
			name: 'md-links',
			link(node, ctx) {
				const m = node.url.match(/^([^:#?]+\.md)(#.*)?$/);
				if (!m) return;
				const target = relative(docsDir, resolve(dirname(file), m[1])).split('\\').join('/');
				const slug = target.replace(/\.md$/, '').replace(/(^|\/)index$/, '');
				ctx.setProperty(node, 'url', posix.join(base, slug, '/') + (m[2] ?? ''));
			},
		};
	};
}
