import { getCollection } from 'astro:content';
import type { APIRoute } from 'astro';
import { sitemapResponse } from '../lib/sitemap';

export const GET: APIRoute = async ({ site }) => {
  const origin = site ?? new URL('https://ilias1988.me');
  const findings = (await getCollection('bugBounty', ({ data }) => !data.draft))
    .sort((a, b) => a.data.order - b.data.order);

  return sitemapResponse(findings.map(({ id, data }) => ({
    loc: new URL(`/bug-bounty/${id}/`, origin).href,
    lastmod: data.updatedAt ?? data.publishedAt,
  })));
};
