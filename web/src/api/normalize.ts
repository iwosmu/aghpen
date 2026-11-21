// Go writes a nil slice as JSON null. The contract types say these fields are
// arrays, so the client turns a null into an empty array once, at the edge,
// instead of every page guarding every list. Fields that are an array in one
// type and a scalar in another (cpe, changes, errors, ports) are not listed:
// their types say "| null" and the pages handle it.
const ARRAY_FIELDS = new Set([
  'allowed_methods', 'blocks', 'buckets', 'certs_expiring', 'classes', 'cookies', 'days', 'evidence', 'exclusions', 'hits',
  'hostnames', 'interest_why', 'invalid', 'issues', 'items', 'matches', 'open_ports', 'paths', 'permissions', 'recent',
  'recent_changes', 'redirects', 'sample_ids', 'sans', 'scope_ids', 'sources', 'spec', 'tags', 'tcp_ack_ports', 'tcp_syn_ports',
  'technologies', 'top_findings', 'top_services', 'trend', 'unstable_hosts', 'valid', 'windows',
]);

export function parseJSON<T>(text: string): T {
  return JSON.parse(text, (key, value) => (value === null && ARRAY_FIELDS.has(key) ? [] : value)) as T;
}
