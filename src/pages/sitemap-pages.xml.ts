import { getCollection } from 'astro:content';
import type { APIRoute } from 'astro';
import { latestDate, sitemapResponse } from '../lib/sitemap';

const HOME_LAST_MODIFIED = new Date('2026-09-01T00:00:00.000Z');
const WRITEUP_COLLECTIONS_LAST_MODIFIED = new Date('2026-09-08T00:00:00.000Z');

export const GET: APIRoute = async ({ site }) => {
  const origin = site ?? new URL('https://ilias1988.me');
  const writeups = await getCollection('writeups', ({ data }) => !data.draft);
  const labs = await getCollection('labs', ({ data }) => !data.draft);
  const bugBounty = await getCollection('bugBounty', ({ data }) => !data.draft);
  const writeupsLastModified = latestDate(
    writeups.map(({ data }) => data.updatedAt ?? data.publishedAt),
    WRITEUP_COLLECTIONS_LAST_MODIFIED,
  );
  const machineWriteups = writeups.filter(({ data }) => data.contentType === 'machine');
  const challengeWriteups = writeups.filter(({ data }) => data.contentType === 'challenge');
  const sherlockWriteups = writeups.filter(({ data }) => data.contentType === 'sherlock');
  const labsLastModified = latestDate(
    labs.map(({ data }) => data.updatedAt ?? data.publishedAt),
    HOME_LAST_MODIFIED,
  );
  const bugBountyLastModified = latestDate(
    bugBounty.map(({ data }) => data.updatedAt ?? data.publishedAt),
    HOME_LAST_MODIFIED,
  );

  return sitemapResponse([
    { loc: new URL('/', origin).href, lastmod: HOME_LAST_MODIFIED },
    { loc: new URL('/writeups/', origin).href, lastmod: writeupsLastModified },
    ...(machineWriteups.length > 0 ? [{
      loc: new URL('/writeups/machines/', origin).href,
      lastmod: latestDate(
        machineWriteups.map(({ data }) => data.updatedAt ?? data.publishedAt),
        WRITEUP_COLLECTIONS_LAST_MODIFIED,
      ),
    }] : []),
    ...(challengeWriteups.length > 0 ? [{
      loc: new URL('/writeups/challenges/', origin).href,
      lastmod: latestDate(
        challengeWriteups.map(({ data }) => data.updatedAt ?? data.publishedAt),
        WRITEUP_COLLECTIONS_LAST_MODIFIED,
      ),
    }] : []),
    ...(sherlockWriteups.length > 0 ? [{
      loc: new URL('/writeups/sherlocks/', origin).href,
      lastmod: latestDate(
        sherlockWriteups.map(({ data }) => data.updatedAt ?? data.publishedAt),
        WRITEUP_COLLECTIONS_LAST_MODIFIED,
      ),
    }] : []),
    { loc: new URL('/labs/', origin).href, lastmod: labsLastModified },
    { loc: new URL('/bug-bounty/', origin).href, lastmod: bugBountyLastModified },
  ]);
};
