import rss from '@astrojs/rss';
import { getCollection } from 'astro:content';
import type { APIRoute } from 'astro';

export const GET: APIRoute = async (context) => {
  const writeups = (await getCollection('writeups', ({ data }) => !data.draft))
    .map((entry) => ({
      title: entry.data.title,
      description: entry.data.summary,
      pubDate: entry.data.publishedAt,
      link: `/writeups/${entry.id}/`,
      categories: entry.data.tags,
    }));

  const labs = (await getCollection('labs', ({ data }) => !data.draft))
    .map((entry) => ({
      title: entry.data.title,
      description: entry.data.summary,
      pubDate: entry.data.publishedAt,
      link: `/labs/${entry.id}/`,
      categories: entry.data.tags,
    }));

  const items = [...writeups, ...labs]
    .sort((a, b) => b.pubDate.valueOf() - a.pubDate.valueOf());

  return rss({
    title: 'Ilias1988 Security Research & Write-ups',
    description: 'Hands-on security research and Hack The Box write-ups by Ilias Georgopoulos: controlled labs, detection engineering, exploitation and lessons learned.',
    site: context.site ?? 'https://ilias1988.me',
    customData: '<language>en-us</language>',
    items,
  });
};
