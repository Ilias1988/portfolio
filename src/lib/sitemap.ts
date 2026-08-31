export interface SitemapEntry {
  loc: string;
  lastmod: Date;
}

const escapeXml = (value: string) =>
  value.replace(/[<>&'\"]/g, (character) => ({
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;',
    "'": '&apos;',
    '"': '&quot;',
  })[character] ?? character);

export const latestDate = (dates: Date[], fallback: Date) =>
  dates.reduce((latest, date) => date.valueOf() > latest.valueOf() ? date : latest, fallback);

export const sitemapResponse = (entries: SitemapEntry[]) => {
  const urls = entries.map(({ loc, lastmod }) => [
    '  <url>',
    `    <loc>${escapeXml(loc)}</loc>`,
    `    <lastmod>${lastmod.toISOString()}</lastmod>`,
    '  </url>',
  ].join('\n')).join('\n');

  return new Response([
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    urls,
    '</urlset>',
  ].join('\n'), {
    headers: { 'Content-Type': 'application/xml; charset=utf-8' },
  });
};

export const sitemapIndexResponse = (entries: SitemapEntry[]) => {
  const sitemaps = entries.map(({ loc, lastmod }) => [
    '  <sitemap>',
    `    <loc>${escapeXml(loc)}</loc>`,
    `    <lastmod>${lastmod.toISOString()}</lastmod>`,
    '  </sitemap>',
  ].join('\n')).join('\n');

  return new Response([
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    sitemaps,
    '</sitemapindex>',
  ].join('\n'), {
    headers: { 'Content-Type': 'application/xml; charset=utf-8' },
  });
};
