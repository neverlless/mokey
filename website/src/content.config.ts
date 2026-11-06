import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

export const collections = {
	docs: defineCollection({
		// Sources stay in ../docs so GitHub links to them keep working.
		loader: glob({
			base: '../docs',
			pattern: ['**/*.md', '!superpowers/**'],
			// Keep file paths verbatim (ROADMAP, security-audit-v1.6) so the MkDocs URLs survive.
			generateId: ({ entry }) => entry.replace(/\.md$/, ''),
		}),
		schema: docsSchema(),
	}),
};
