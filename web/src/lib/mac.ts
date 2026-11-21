/** A locally administered MAC address (bit 1 of the first octet set: second hex digit 2, 6, A or E). Docker and VMs use these; no vendor owns them. */
export function isLocalMac(mac: string): boolean {
  const m = mac.trim().match(/^[0-9a-f]([0-9a-f])/i);
  return Boolean(m && '26ae'.includes(m[1].toLowerCase()));
}
