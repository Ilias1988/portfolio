import { getCollection } from 'astro:content';
import type { APIRoute } from 'astro';
import { latestDate, sitemapResponse } from '../lib/sitemap';

const HOME_LAST_MODIFIED = new Date('2026-08-31T00:00:00.000Z');

export const GET: APIRoute = async ({ site }) => {
  const origin = site ?? new URL('https://ilias1988.me');
  const writeups = await getCollection('writeups', ({ data }) => !data.draft);
  const archiveLastModified = latestDate(
    writeups.map(({ data }) => data.updatedAt ?? data.publishedAt),
    HOME_LAST_MODIFIED,
  );

  return sitemapResponse([
    { loc: new URL('/', origin).href, lastmod: HOME_LAST_MODIFIED },
    { loc: new URL('/writeups/', origin).href, lastmod: archiveLastModified },
  ]);
};
