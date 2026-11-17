import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { gzipSync } from 'node:zlib';
import { asUrl, decodeEntities, fetchPage, htmlToText, isPrivateAddress } from '../server/extract.ts';

test('recognises a lone link, with or without scheme', () => {
  assert.equal(asUrl('https://example.com/a?b=1'), 'https://example.com/a?b=1');
  assert.equal(asUrl('  www.example.se/artikel '), 'https://www.example.se/artikel');
  assert.equal(asUrl('elcyklar i glesbygd'), null);
  assert.equal(asUrl('läs https://example.com'), null, 'text with a link in it is text');
  assert.equal(asUrl('javascript:alert(1)'), null);
  assert.equal(asUrl('ftp://example.com'), null);
});

test('decodes named and numeric entities, including Swedish letters', () => {
  assert.equal(decodeEntities('R&auml;ksm&ouml;rg&aring;s &amp; &#229;&#xE4; &hellip;'), 'Räksmörgås & åä …');
  assert.equal(decodeEntities('&bogus; &#0;'), '&bogus; &#0;');
});

test('extracts the article and drops scripts, navigation and footers', () => {
  const html = `<!doctype html><html><head>
    <title>Fallback title</title>
    <meta property="og:title" content="Cykelbibliotek i Växjö">
    <style>.x{color:red}</style><script>var secret = 1;</script></head>
    <body><nav>Meny Hem Om</nav>
    <article><h1>Cykelbibliotek</h1><p>Kommunen l&aring;nar ut <b>lastcyklar</b>.</p>
    <script>tracking()</script><p>Andra stycket.<br>Ny rad.</p></article>
    <footer>© 2026</footer></body></html>`;
  const { title, text } = htmlToText(html);
  assert.equal(title, 'Cykelbibliotek i Växjö');
  assert.match(text, /^Cykelbibliotek\n\nKommunen lånar ut lastcyklar \./);
  assert.match(text, /Andra stycket\.\nNy rad\./);
  for (const junk of ['secret', 'tracking', 'Meny', '©', 'color:red']) assert.ok(!text.includes(junk), junk);
});

test('falls back to <title> and <body> when there is no article', () => {
  const { title, text } = htmlToText('<title>T &amp; T</title><body><div>Hej</div><div>då</div></body>');
  assert.equal(title, 'T & T');
  assert.equal(text, 'Hej\n\ndå');
});

test('caps very long pages', () => {
  const { text } = htmlToText(`<body><p>${'ord '.repeat(5000)}</p></body>`);
  assert.ok(text.length <= 6000 + 4);
  assert.ok(text.endsWith('[…]'));
});

test('private, local and reserved addresses are recognised, in every spelling', () => {
  for (const ip of ['127.0.0.1', '127.8.9.10', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254',
    '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '::1', '::', '[::1]', 'fe80::1', 'fd00::1', 'fc00::1',
    '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:a9fe:a9fe', '64:ff9b::7f00:1', '64:ff9b::10.0.0.1', '64:ff9b:1::a9fe:a9fe', '64:ff9b:1:0:a:0:100:0',
    '64:ff9b:1:0:c0:a801:100:0', '64:ff9b:1:a00:0:100:808:808', '::ffff:0:7f00:1', '3fff::1', '5f00::1',
    '64:ff9b::ffff:7f00:1', '64:ff9b:0:0:1::7f00:1', '64:ff9b:7f00:1::', '64:ff9b:a9:fea9:fe::',
    '2002:7f00:1::', '2002:c0a8:101::1', '::7f00:1', '192.88.99.1', '2001::1', 'ff02::1', 'localhost', 'nonsense']) {
    assert.equal(isPrivateAddress(ip), true, ip);
  }
  for (const ip of ['93.184.216.34', '8.8.8.8', '172.32.0.1', '2606:4700::1111', '[2a00:1450:4001::200e]',
    '64:ff9b::5db8:d822', '64:ff9b::93.184.216.34', '2002:5db8:d822::1']) {
    assert.equal(isPrivateAddress(ip), false, `${ip} (NAT64 and 6to4 wrapping a public address are fine)`);
  }
});

// A local page server, so these tests need no network.
async function pages(routes: Record<string, (res: ServerResponse) => void>) {
  const notFound = (r: ServerResponse) => r.writeHead(404).end();
  const server: Server = createServer((req, res) => (routes[req.url ?? ''] ?? notFound)(res));
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return { server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}
const article = '<title>Sida</title><body><article><p>' + 'Lånecyklar i glesbygd. '.repeat(10) + '</p></article></body>';
const allowLoopback = (ip: string) => ip !== '127.0.0.1' && isPrivateAddress(ip);
/** Lets only the first address check through: the test server itself; every later hop gets the real rule. */
const firstHopOnly = () => {
  let n = 0;
  return (ip: string) => (n++ === 0 ? false : isPrivateAddress(ip));
};

test('a pasted link cannot reach this machine, the LAN or a metadata service', async () => {
  const { server, base } = await pages({ '/': (res) => res.writeHead(200, { 'Content-Type': 'text/html' }).end(article) });
  const port = new URL(base).port;
  try {
    for (const url of [base, `http://localhost:${port}/`, `http://[::1]:${port}/`, `http://2130706433:${port}/`, `http://0x7f.1:${port}/`,
      `http://[::ffff:127.0.0.1]:${port}/`, 'http://169.254.169.254/latest/meta-data/', 'http://192.168.1.1/', 'http://0.0.0.0/']) {
      await assert.rejects(fetchPage(url), /private or local address/, url);
    }
  } finally {
    server.close();
  }
});

test('every redirect hop is checked again; the hop count is capped', async () => {
  const { server, base } = await pages({
    '/to-metadata': (res) => res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' }).end(),
    '/to-localhost': (res) => res.writeHead(301, { Location: 'http://localhost/admin' }).end(),
    '/to-file': (res) => res.writeHead(302, { Location: 'file:///etc/passwd' }).end(),
    '/loop': (res) => res.writeHead(307, { Location: '/loop' }).end(),
    '/hop': (res) => res.writeHead(302, { Location: '/page' }).end(),
    '/page': (res) => res.writeHead(200, { 'Content-Type': 'text/html' }).end(article),
  });
  try {
    await assert.rejects(fetchPage(base + '/to-metadata', { isBlocked: allowLoopback }), /169\.254\.169\.254/);
    await assert.rejects(fetchPage(base + '/to-localhost', { isBlocked: firstHopOnly() }), /localhost points to a private or local address/, 'refused at lookup, whatever localhost resolves to');
    await assert.rejects(fetchPage(base + '/to-file', { isBlocked: allowLoopback }), /Not a web link/);
    await assert.rejects(fetchPage(base + '/loop', { isBlocked: allowLoopback }), /Too many redirects/);
    assert.equal((await fetchPage(base + '/hop', { isBlocked: allowLoopback })).title, 'Sida', 'a redirect to a public page is followed');
  } finally {
    server.close();
  }
});

test('reads a public page: gzip decoded, body capped, non-pages refused', async () => {
  const { server, base } = await pages({
    '/gz': (res) => res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Encoding': 'gzip' }).end(gzipSync(article)),
    '/huge': (res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      const chunk = '<p>' + 'x'.repeat(65_000) + '</p>';
      const more = () => { while (res.write(chunk)); };
      res.on('drain', more);
      more();
      res.on('close', () => res.off('drain', more));
    },
    '/pdf': (res) => res.writeHead(200, { 'Content-Type': 'application/pdf' }).end('%PDF'),
    '/gone': (res) => res.writeHead(404).end(),
  });
  try {
    const page = await fetchPage(base + '/gz', { isBlocked: allowLoopback });
    assert.equal(page.title, 'Sida');
    assert.match(page.text, /^Lånecyklar i glesbygd\./);
    const huge = await fetchPage(base + '/huge', { isBlocked: allowLoopback });
    assert.ok(huge.text.length <= 6000 + 4, 'an endless page is cut off, not buffered');
    await assert.rejects(fetchPage(base + '/pdf', { isBlocked: allowLoopback }), /Not a web page/);
    await assert.rejects(fetchPage(base + '/gone', { isBlocked: allowLoopback }), /HTTP 404/);
  } finally {
    server.closeAllConnections();
    server.close();
  }
});
