/** The operator lock (CZUJKA_ALLOWED_NETWORKS): helpers for the UI. */

/** True when a refusal text from the server names the operator lock. */
export function isLockRefusal(text: string | undefined | null): boolean {
  return Boolean(text && /CZUJKA_ALLOWED_NETWORKS|operator lock|blokad\w* operatora/i.test(text));
}

/**
 * The Polish (or English) sentence for a 422 the server gives in English when the lock refuses something.
 * Returns null for any other message.
 */
export function lockMessage(msg: string, lang: 'pl' | 'en'): string | null {
  const net = msg.match(/allowed_networks: (\S+) lies outside the operator lock \(CZUJKA_ALLOWED_NETWORKS: ([^)]+)\)/)
    ?? msg.match(/allowed_networks: sieć (\S+) leży poza blokadą operatora \(CZUJKA_ALLOWED_NETWORKS: ([^)]+)\)/);
  if (net) {
    return lang === 'pl'
      ? 'Sieć ' + net[1] + ' leży poza blokadą operatora (' + net[2] + ').'
      : 'The network ' + net[1] + ' is outside the operator lock (' + net[2] + ').';
  }
  const all = msg.match(/every target lies outside the allowed networks.*?operator lock \(CZUJKA_ALLOWED_NETWORKS: ([^)]+)\);?\s*(.*)$/)
    ?? msg.match(/każdy cel leży poza dozwolonymi sieciami.*?blokadą operatora \(CZUJKA_ALLOWED_NETWORKS: ([^)]+)\);?\s*(.*)$/);
  if (all) {
    const lead = lang === 'pl'
      ? 'Żaden adres nie leży w dozwolonych sieciach (' + all[1] + ').'
      : 'No address is inside the allowed networks (' + all[1] + ').';
    return all[2] ? lead + ' ' + all[2] : lead;
  }
  return null;
}

type V4 = { base: number; bits: number };

function parseV4(s: string): V4 | null {
  const m = s.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if (!m) return null;
  const o = m.slice(1, 5).map(Number);
  if (o.some((x) => x > 255)) return null;
  const bits = m[5] === undefined ? 32 : Number(m[5]);
  if (bits > 32) return null;
  const ip = ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: (ip & mask) >>> 0, bits };
}

function inside(p: V4, q: V4): boolean {
  if (q.bits > p.bits) return false;
  const mask = q.bits === 0 ? 0 : (0xffffffff << (32 - q.bits)) >>> 0;
  return ((p.base & mask) >>> 0) === q.base;
}

/**
 * Entries (IPv4 address or CIDR) that lie outside every network of the lock.
 * Entries the UI cannot parse (IPv6, names, ranges) are left to the server.
 */
export function outsideLock(entries: string[], lock: string[]): string[] {
  const locks = lock.map(parseV4).filter((x): x is V4 => x !== null);
  if (!locks.length) return [];
  return entries.filter((e) => {
    const p = parseV4(e);
    return p !== null && !locks.some((q) => inside(p, q));
  });
}
