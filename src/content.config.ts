import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { z } from 'astro/zod';

const writeups = defineCollection({
  loader: glob({
    base: './src/content/writeups',
    pattern: '**/*.{md,mdx}',
  }),
  schema: z.object({
    title: z.string().min(5),
    summary: z.string().min(30).max(240),
    platform: z.literal('Hack The Box'),
    contentType: z.enum(['machine', 'challenge', 'sherlock', 'starting-point', 'academy']),
    publicationPolicy: z.enum(['retired', 'starting-point', 'academy-tier-0']),
    difficulty: z.enum(['Very Easy', 'Easy', 'Medium', 'Hard', 'Insane']).optional(),
    os: z.enum(['Linux', 'Windows', 'Other']).optional(),
    solvedAt: z.coerce.date(),
    publishedAt: z.coerce.date(),
    updatedAt: z.coerce.date().optional(),
    tags: z.array(z.string()).min(1),
    tools: z.array(z.string()).default([]),
    cves: z.array(z.string()).default([]),
    htbUrl: z.url().optional(),
    cover: z.string().startsWith('/').optional(),
    coverAlt: z.string().min(5).optional(),
    featured: z.boolean().default(false),
    draft: z.boolean().default(false),
  }),
});

export const collections = { writeups };
