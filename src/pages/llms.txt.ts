import { getCollection } from 'astro:content';
import type { APIRoute } from 'astro';

const clean = (value: string) => value.replace(/\s+/g, ' ').trim();

export const GET: APIRoute = async ({ site }) => {
  const origin = site ?? new URL('https://ilias1988.me');
  const absolute = (path: string) => new URL(path, origin).href;

  const writeups = (await getCollection('writeups', ({ data }) => !data.draft))
    .sort((a, b) => b.data.publishedAt.valueOf() - a.data.publishedAt.valueOf());
  const labs = (await getCollection('labs', ({ data }) => !data.draft))
    .sort((a, b) => b.data.publishedAt.valueOf() - a.data.publishedAt.valueOf());

  const writeupSections = [
    { type: 'machine', heading: 'Hack The Box Machines' },
    { type: 'challenge', heading: 'Hack The Box Challenges' },
    { type: 'sherlock', heading: 'Hack The Box Sherlocks' },
  ].flatMap(({ type, heading }) => {
    const entries = writeups.filter(({ data }) => data.contentType === type);
    if (entries.length === 0) return [];

    return [
      `## ${heading}`,
      '',
      ...entries.map(({ id, data }) =>
        `- [${data.title}](${absolute(`/writeups/${id}/`)}): ${clean(data.summary)}`,
      ),
      '',
    ];
  });

  const labLines = labs.length > 0
    ? [
        '## Security Research Labs',
        '',
        ...labs.map(({ id, data }) =>
          `- [${data.title}](${absolute(`/labs/${id}/`)}): ${clean(data.summary)}`,
        ),
        '',
      ]
    : [];

  const body = [
    '# Ilias Georgopoulos Cybersecurity Portfolio',
    '',
    '> The official portfolio of Ilias Georgopoulos (Ilias1988), focused on practical cybersecurity, penetration testing, Hack The Box write-ups, controlled security research, detection engineering and offensive-security tooling.',
    '',
    'Use this file as a curated map of the public site. The linked pages are the canonical sources for claims about the author, projects, lab results and challenge solutions. Hack The Box write-ups are evidence-led, sanitized and limited to content approved for publication; flags, personal secrets and original challenge packages are not published.',
    '',
    '## Start Here',
    '',
    `- [Portfolio home](${absolute('/')}): Profile, skills, certifications, selected tools, projects and contact links.`,
    `- [Write-ups archive](${absolute('/writeups/')}): All published Hack The Box Machines, Challenges and Sherlocks.`,
    `- [Security research labs](${absolute('/labs/')}): Controlled red-team, Windows, network-security and detection-engineering experiments.`,
    `- [RSS feed](${absolute('/rss.xml')}): Chronological feed of public write-ups.`,
    `- [Sitemap index](${absolute('/sitemap-index.xml')}): Machine-readable inventory of public site URLs.`,
    '',
    ...writeupSections,
    ...labLines,
    '## Optional',
    '',
    '- [GitHub](https://github.com/Ilias1988): Source repositories and security tooling by Ilias1988.',
    '- [LinkedIn](https://www.linkedin.com/in/ilias-georgopoulos-b491a3371/): Professional profile and career updates.',
    '- [Hack The Box profile](https://profile.hackthebox.com/profile/019f1af0-0e02-70cb-9c8a-41589216a056): Hack The Box activity and progress.',
    '- [TryHackMe profile](https://tryhackme.com/p/Ilias1988): Hands-on learning profile and achievements.',
    '- [YouTube](https://www.youtube.com/@Ilias-1988): Video content from Ilias1988.',
    '',
  ].join('\n');

  return new Response(body, {
    headers: {
      'Content-Type': 'text/markdown; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    },
  });
};
