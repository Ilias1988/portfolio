import rss from '@astrojs/rss';
import { getCollection } from 'astro:content';
import type { APIRoute } from 'astro';

export const GET: APIRoute = async (context) => {
  const writeups = (await getCollection('writeups', ({ data }) => !data.draft))
    .sort((a, b) => b.data.publishedAt.valueOf() - a.data.publishedAt.valueOf());

  return rss({
    title: 'Ilias1988 Security Write-ups',
    description: 'Hack The Box write-ups by Ilias Georgopoulos: enumeration, exploitation, privilege escalation and lessons learned.',
    site: context.site ?? 'https://ilias1988.me',
    customData: '<language>en-us</language>',
    items: writeups.map((entry) => ({
      title: entry.data.title,
      description: entry.data.summary,
      pubDate: entry.data.publishedAt,
      link: `/writeups/${entry.id}/`,
      categories: entry.data.tags,
    })),
  });
};
