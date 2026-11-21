import { plural } from '../i18n';

/**
 * A port list for one table cell: "top-1000 + 43 porty", "80, 443, 8080 + 12 portów".
 * Short lists stay as they are. The full list is on the profile page.
 */
export function portsShort(spec: string, keep = 3): string {
  const parts = spec.split(',').map((s) => s.trim()).filter(Boolean);
  if (parts.length <= keep + 1) return parts.join(', ');
  const lead = /^top-\d+$/i.test(parts[0]) ? [parts[0]] : parts.slice(0, keep);
  const rest = parts.length - lead.length;
  return lead.join(', ') + ' + ' + rest + ' ' + plural(rest, ['port', 'porty', 'portów'], ['port', 'ports']);
}
