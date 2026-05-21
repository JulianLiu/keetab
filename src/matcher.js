// URL parsing + entry ranking. Adapted from
// Tusk/src/lib/utils.js and Tusk/services/keepassService.js:94 (rankEntries).

import { resolveValue } from './kdbx.js';

export function parseUrl(url) {
  if (!url) return null;
  let u = url;
  if (u.indexOf('http') !== 0) u = 'http://' + u;
  try {
    const a = document.createElement('a');
    a.href = u;
    return a;
  } catch {
    return null;
  }
}

export function getValidTokens(s) {
  if (!s) return [];
  return s
    .toLowerCase()
    .split(/\.|\s|\//)
    .filter((t) => t && t !== 'com' && t !== 'www' && t.length > 1);
}

// Apply Tusk's ranking. `siteUrl` is a parsed anchor element.
export function rankEntries(entries, siteUrl, title, allEntries) {
  if (!siteUrl) {
    for (const e of entries) e.matchRank = 0;
    return entries;
  }
  const siteTokens = getValidTokens(`${siteUrl.hostname} ${title || ''}`);

  for (const entry of entries) {
    const entryUrl = resolveValue(entry, 'url', allEntries);
    const entryTitle = resolveValue(entry, 'title', allEntries);

    const origins = [parseUrl(entryUrl)].filter(Boolean);
    const tuskExtra = resolveValue(entry, 'tuskUrls', allEntries);
    if (tuskExtra) {
      for (const u of tuskExtra.split(',')) {
        const p = parseUrl(u.trim());
        if (p) origins.push(p);
      }
    }

    let rank = 0;
    if (origins.some((a) => a.origin === siteUrl.origin))        rank = 100;
    else if (origins.some((a) => a.host === siteUrl.host))       rank = 10;
    else if (origins.some((a) => a.hostname === siteUrl.hostname)) rank = -100;

    if (entryTitle && title && entryTitle.toLowerCase() === title.toLowerCase()) rank += 1;
    if (entryTitle && entryTitle.toLowerCase() === siteUrl.hostname.toLowerCase()) rank += 1;
    if (entryUrl && siteUrl.hostname.indexOf(entryUrl.toLowerCase()) > -1) rank += 0.9;
    if (entryTitle && siteUrl.hostname.indexOf(entryTitle.toLowerCase()) > -1) rank += 0.9;

    const tokenSrc = origins.map((o) => o.hostname).join('.') + '.' + (entryTitle || '');
    const entryTokens = getValidTokens(tokenSrc);
    for (const t1 of entryTokens) {
      for (const t2 of siteTokens) {
        if (t1 === t2) rank += 0.2;
      }
    }

    entry.matchRank = rank;
  }
  return entries;
}

// Simple text search across visible fields.
export function filterByText(entries, query, allEntries) {
  const q = (query || '').trim().toLowerCase();
  if (!q) return entries;
  return entries.filter((entry) => {
    const fields = ['title', 'userName', 'url', 'notes', 'groupPath', 'tags'];
    for (const f of fields) {
      const v = resolveValue(entry, f, allEntries);
      if (v && v.toLowerCase().indexOf(q) !== -1) return true;
    }
    return false;
  });
}

// Sort: matchRank desc, then title asc.
export function sortEntries(entries, allEntries) {
  return entries.slice().sort((a, b) => {
    const ra = a.matchRank || 0;
    const rb = b.matchRank || 0;
    if (rb !== ra) return rb - ra;
    const ta = (resolveValue(a, 'title', allEntries) || '').toLowerCase();
    const tb = (resolveValue(b, 'title', allEntries) || '').toLowerCase();
    return ta.localeCompare(tb);
  });
}
