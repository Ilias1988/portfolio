import { getCollection } from 'astro:content';
import type { APIRoute } from 'astro';
import { sitemapResponse } from '../lib/sitemap';

export const GET: APIRoute = async ({ site }) => {
  const origin = site ?? new URL('https://ilias1988.me');
  const writeups = (await getCollection('writeups', ({ data }) => !data.draft))
    .sort((a, b) => b.data.publishedAt.valueOf() - a.data.publishedAt.valueOf());

  return sitemapResponse(writeups.map(({ id, data }) => ({
    loc: new URL(`/writeups/${id}/`, origin).href,
    lastmod: data.updatedAt ?? data.publishedAt,
  })));
};
