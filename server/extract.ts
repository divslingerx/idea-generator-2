// Seeds from a link: fetch the page and pull out readable text.
// Deliberately simple: prefer <article>, then <main>, then <body>; drop
// scripts, navigation and other chrome; keep paragraph breaks.

import { lookup as dnsLookup, type LookupAddress } from 'node:dns';
import { request as httpRequest, type IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { BlockList, isIP, type LookupFunction } from 'node:net';
import { pipeline } from 'node:stream';
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib';

const MAX_BYTES = 2_000_000;
const MAX_CHARS = 6000;

/** A single URL (optionally without scheme), or null if the text is not one. */
export function asUrl(text: string): string | null {
  const t = text.trim();
  if (/\s/.test(t)) return null;
  const candidate = /^https?:\/\//i.test(t) ? t : /^www\.[^\s.]+\.\S+$/i.test(t) ? `https://${t}` : null;
  if (!candidate) return null;
  try {
    const u = new URL(candidate);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
  } catch {
    return null;
  }
}

const ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ndash: '–', mdash: '—',
  hellip: '…', laquo: '«', raquo: '»', rsquo: '’', lsquo: '‘', rdquo: '”', ldquo: '“',
  aring: 'å', auml: 'ä', ouml: 'ö', Aring: 'Å', Auml: 'Ä', Ouml: 'Ö', eacute: 'é',
};

export function decodeEntities(s: string) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === '#') {
      const code = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : m;
    }
    return ENTITIES[e] ?? ENTITIES[e.toLowerCase()] ?? m;
  });
}

export function htmlToText(html: string): { title: string; text: string } {
  const titleMatch =
    html.match(/<meta[^>]+property=["']og:title["'][^>]*content=["']([^"']+)["']/i) ||
    html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? decodeEntities(titleMatch[1]).replace(/\s+/g, ' ').trim() : '';

  let body = html.replace(/<!--[\s\S]*?-->/g, '');
  for (const tag of ['script', 'style', 'noscript', 'svg', 'nav', 'header', 'footer', 'aside', 'form', 'template', 'iframe']) {
    body = body.replace(new RegExp(`<${tag}\\b[\\s\\S]*?<\\/${tag}>`, 'gi'), ' ');
  }
  const pick = (tag: string) => body.match(new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i'))?.[1];
  const main = pick('article') ?? pick('main') ?? pick('body') ?? body;

  const text = decodeEntities(
    main
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<\/(p|div|h[1-6]|li|blockquote|section|tr)>/gi, '\n\n')
      .replace(/<[^>]+>/g, ' '),
  )
    .split('\n')
    .map((l) => l.replace(/[ \t ]+/g, ' ').trim())
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  return { title, text: text.length > MAX_CHARS ? `${text.slice(0, MAX_CHARS)}\n[…]` : text };
}

// ---- fetching: public web pages only
//
// A pasted link must not reach this machine, the LAN or a cloud metadata service
// (169.254.169.254). Every address is checked at connect time, in the lookup the
// socket itself uses, so a DNS answer cannot change between the check and the
// connection (rebinding). IP-literal hosts skip lookup, so they are checked up front.
// Redirects are followed by hand, and each hop is checked again.

const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 12_000;

const PRIVATE = new BlockList();
for (const [net, bits] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
] as const) PRIVATE.addSubnet(net, bits, 'ipv4');
// IPv4-mapped (::ffff:a.b.c.d) needs no rule: BlockList checks it against the IPv4 ranges above.
// Well-known NAT64 (64:ff9b::/96) and 6to4 (2002::/16) are not blocked whole: IPv6-only networks reach
// every IPv4 site through NAT64. isPrivateAddress() checks the IPv4 address they carry instead.
// Local-use NAT64 (64:ff9b:1::/48) may put the IPv4 address in middle bits (RFC 6052 /48–/64 layouts),
// so it is blocked whole, like Teredo, SIIT (::ffff:0:a.b.c.d) and the other special ranges. The rest of
// 64:ff9b::/32 is not standardised but could be configured as a NAT64 prefix: blocked too. (The /96 is
// handled in code before the block list is consulted, so well-known NAT64 to public sites still works.)
for (const [net, bits] of [
  ['::', 96], ['::ffff:0:0:0', 96], ['64:ff9b::', 32], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 32], ['2001:db8::', 32],
  ['3fff::', 20], ['5f00::', 16], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8],
] as const) PRIVATE.addSubnet(net, bits, 'ipv6');

/** The eight 16-bit groups of an IPv6 address (zone dropped, embedded dotted quad allowed), or null. */
function hextets(ip: string): number[] | null {
  let s = ip.split('%')[0].toLowerCase();
  const quad = s.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (quad) {
    const [a, b, c, d] = quad.slice(1).map(Number);
    s = `${s.slice(0, quad.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, tail, extra] = s.split('::');
  if (extra !== undefined) return null;
  const left = head ? head.split(':') : [];
  const right = tail === undefined ? [] : tail ? tail.split(':') : [];
  const fill = tail === undefined ? 0 : 8 - left.length - right.length;
  const groups = [...left, ...Array(Math.max(0, fill)).fill('0'), ...right].map((g) => parseInt(g, 16));
  return groups.length === 8 && groups.every((g) => g >= 0 && g <= 0xffff) ? groups : null;
}
const quadOf = (hi: number, lo: number) => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;

/** Loopback, private, link-local, reserved and the like. Anything that is not an IP address counts as private. */
export function isPrivateAddress(ip: string): boolean {
  const a = ip.replace(/^\[|\]$/g, '');
  const v = isIP(a);
  if (v === 0) return true;
  if (v === 6) {
    const h = hextets(a);
    if (!h) return true;
    // Well-known NAT64 (64:ff9b::/96): the IPv4 address is the last 32 bits.
    if (h[0] === 0x64 && h[1] === 0xff9b && h.slice(2, 6).every((x) => x === 0)) return isPrivateAddress(quadOf(h[6], h[7]));
    // 6to4 (2002::/16): the IPv4 address is bits 16–48.
    if (h[0] === 0x2002) return isPrivateAddress(quadOf(h[1], h[2]));
  }
  return PRIVATE.check(a, v === 6 ? 'ipv6' : 'ipv4');
}

const blockedError = (host: string, ip: string) =>
  Object.assign(new Error(`${host} points to a private or local address (${ip}); only public web pages can be read`), { code: 'private_address' });

/** dns.lookup that refuses to hand a blocked address to the socket. */
function checkedLookup(isBlocked: (ip: string) => boolean): LookupFunction {
  return (hostname, options, cb) => {
    dnsLookup(hostname, { ...options, all: true }, (err, addrs: LookupAddress[]) => {
      if (err) return cb(err, '');
      const bad = addrs.find((a) => isBlocked(a.address));
      if (bad || !addrs.length) return cb(blockedError(hostname, bad?.address ?? 'none'), '');
      if (options.all) cb(null, addrs);
      else cb(null, addrs[0].address, addrs[0].family);
    });
  };
}

const HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36',
  Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'sv,en;q=0.8',
  'Accept-Encoding': 'gzip, deflate, br',
};

function get(url: URL, signal: AbortSignal, isBlocked: (ip: string) => boolean): Promise<IncomingMessage> {
  return new Promise((resolve, reject) => {
    const host = url.hostname.replace(/^\[|\]$/g, '');
    if (isIP(host) && isBlocked(host)) return reject(blockedError(host, host));
    const send = url.protocol === 'https:' ? httpsRequest : httpRequest;
    const req = send(url, { headers: HEADERS, signal, lookup: checkedLookup(isBlocked) }, resolve);
    req.on('error', reject);
    req.end();
  });
}

/** The body, decompressed, at most MAX_BYTES: a huge or endless page is cut off, not buffered. */
async function readCapped(res: IncomingMessage): Promise<Buffer> {
  const enc = String(res.headers['content-encoding'] ?? '').trim().toLowerCase();
  const decoder = enc === 'gzip' || enc === 'x-gzip' ? createGunzip() : enc === 'deflate' ? createInflate() : enc === 'br' ? createBrotliDecompress() : null;
  const body = decoder ? pipeline(res, decoder, () => {}) : res;
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const c of body as AsyncIterable<Buffer>) {
      chunks.push(c);
      size += c.length;
      if (size >= MAX_BYTES) break;
    }
  } finally {
    res.destroy();
  }
  return Buffer.concat(chunks).subarray(0, MAX_BYTES);
}

/** opts.isBlocked is for tests; by default every private and local address is refused. */
export async function fetchPage(url: string, opts: { isBlocked?: (ip: string) => boolean } = {}): Promise<{ title: string; text: string }> {
  const isBlocked = opts.isBlocked ?? isPrivateAddress;
  const signal = AbortSignal.timeout(TIMEOUT_MS);
  try {
    return await fetchHops(new URL(url), signal, isBlocked);
  } catch (e) {
    if (signal.aborted) throw new Error(`Timed out after ${TIMEOUT_MS / 1000} s`);
    throw e;
  }
}

async function fetchHops(start: URL, signal: AbortSignal, isBlocked: (ip: string) => boolean): Promise<{ title: string; text: string }> {
  let current = start;
  for (let hop = 0; ; hop++) {
    if (current.protocol !== 'http:' && current.protocol !== 'https:') throw new Error(`Not a web link (${current.protocol})`);
    const res = await get(current, signal, isBlocked);
    const status = res.statusCode ?? 0;
    if (status >= 300 && status < 400 && res.headers.location) {
      res.resume();
      if (hop >= MAX_REDIRECTS) throw new Error('Too many redirects');
      current = new URL(res.headers.location, current);
      continue;
    }
    if (status < 200 || status >= 300) {
      res.resume();
      throw new Error(`HTTP ${status}`);
    }
    const type = String(res.headers['content-type'] ?? '');
    if (!/html|text\/plain/i.test(type)) {
      res.destroy();
      throw new Error(`Not a web page (${type || 'unknown type'})`);
    }
    const html = new TextDecoder('utf-8').decode(await readCapped(res));
    return /text\/plain/i.test(type) ? { title: '', text: html.slice(0, MAX_CHARS) } : htmlToText(html);
  }
}
