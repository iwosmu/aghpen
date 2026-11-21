import type { SVGProps } from 'react';

// One authored icon set: 16px grid, 1.5px stroke, square caps to match the ruled look.
const P: Record<string, string> = {
  plus: 'M8 3v10M3 8h10',
  minus: 'M3 8h10',
  delta: 'M8 3.2 13.2 12.5H2.8Z',
  wave: 'M1.5 8c1.6-3.4 3.2-3.4 4.8 0s3.2 3.4 4.8 0 2.4-2.6 3.4-1.4',
  check: 'M3 8.5 6.5 12 13 4.5',
  x: 'M4 4l8 8M12 4l-8 8',
  chevronRight: 'M6 3.5 10.5 8 6 12.5',
  chevronDown: 'M3.5 6 8 10.5 12.5 6',
  chevronLeft: 'M10 3.5 5.5 8 10 12.5',
  arrowRight: 'M3 8h10M9 4l4 4-4 4',
  arrowUp: 'M8 13V3M4 7l4-4 4 4',
  arrowDown: 'M8 3v10M4 9l4 4 4-4',
  search: 'M7 12A5 5 0 1 0 7 2a5 5 0 0 0 0 10ZM10.7 10.7 14 14',
  play: 'M5 3.5v9l7.5-4.5Z',
  pause: 'M5 3.5v9M11 3.5v9',
  stop: 'M4 4h8v8H4Z',
  shield: 'M8 2 13 4v4c0 3-2.2 5-5 6-2.8-1-5-3-5-6V4Z',
  user: 'M8 8a2.7 2.7 0 1 0 0-5.4A2.7 2.7 0 0 0 8 8ZM3 13.5c.6-2.4 2.6-3.6 5-3.6s4.4 1.2 5 3.6',
  lock: 'M4 7.5h8v6H4ZM5.8 7.5V5.4a2.2 2.2 0 0 1 4.4 0v2.1',
  external: 'M9 3h4v4M13 3 7.5 8.5M11 9.5V13H3V5h3.5',
  download: 'M8 2.5v8M4.5 7.5 8 11l3.5-3.5M3 13.5h10',
  print: 'M4.5 6V2.5h7V6M4.5 11.5H2.5v-5.5h11v5.5h-2M4.5 9.5h7v4h-7Z',
  upload: 'M8 11V3M4.5 6 8 2.5 11.5 6M3 13.5h10',
  edit: 'M3 13h2.5L13 5.5 10.5 3 3 10.5ZM9.5 4l2.5 2.5',
  trash: 'M3 4.5h10M6 4.5V3h4v1.5M4.5 4.5l.6 9h5.8l.6-9M6.8 7v4M9.2 7v4',
  filter: 'M2.5 3.5h11L9.5 8.5v4l-3 1v-5Z',
  sun: 'M8 10.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5ZM8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M3.4 12.6l1.4-1.4M11.2 4.8l1.4-1.4',
  moon: 'M13 9.5A5.5 5.5 0 0 1 6.5 3 5.5 5.5 0 1 0 13 9.5Z',
  alert: 'M8 2.5 14 13H2ZM8 6.5v3M8 11.2v.3',
  clock: 'M8 14A6 6 0 1 0 8 2a6 6 0 0 0 0 12ZM8 4.5V8l2.5 1.5',
  undo: 'M3 7h6.5a3 3 0 0 1 0 6H6M3 7l3-3M3 7l3 3',
  copy: 'M5.5 5.5h7v8h-7ZM3.5 10.5v-8h7',
  menu: 'M2.5 4.5h11M2.5 8h11M2.5 11.5h11',
  eye: 'M1.5 8S4 3.5 8 3.5 14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8ZM8 10a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z',
  logout: 'M6.5 2.5h-4v11h4M6.5 8H14M11 5l3 3-3 3',
  dashboard: 'M2.5 2.5h4.5v6H2.5ZM9 2.5h4.5v3.5H9ZM9 8h4.5v5.5H9ZM2.5 10.5h4.5v3H2.5Z',
  runs: 'M2.5 2.5h11v11h-11ZM2.5 6.2h11M2.5 9.8h11M6.2 2.5v11M9.8 2.5v11',
  hosts: 'M2.5 3h11v4h-11ZM2.5 9h11v4h-11ZM4.6 5h.2M4.6 11h.2',
  services: 'M8 2.5v3M8 10.5v3M2.5 8h3M10.5 8h3M8 10.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Z',
  changes: 'M3 5h8.5M9 2.5 11.5 5 9 7.5M13 11H4.5M7 8.5 4.5 11 7 13.5',
  findings: 'M3 2.5h7l3 3v8H3ZM10 2.5v3h3M5.5 8.5h5M5.5 11h5',
  signatures: 'M2.5 12.5c1.5-6 3-8 4.2-8 2.2 0-1.4 7.5.8 7.5 1.4 0 1.6-3.4 3-3.4 1 0 .8 1.8 3 1.8',
  targets: 'M8 14A6 6 0 1 0 8 2a6 6 0 0 0 0 12ZM8 10.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5ZM8 .8v2.4M8 12.8v2.4M.8 8h2.4M12.8 8h2.4',
  profiles: 'M2.5 4.5h7M12 4.5h1.5M2.5 11.5h1.5M6.5 11.5h7M9.5 3v3h2.500V3ZM4 10v3h2.500v-3Z',
  transfer: 'M5 2.5v8M2.5 8 5 10.5 7.500 8M11 13.5v-8M8.500 8 11 5.500 13.500 8',
  admin: 'M8 9.800a1.800 1.800 0 1 0 0-3.600 1.800 1.800 0 0 0 0 3.600ZM8 2v1.800M8 12.200V14M2 8h1.800M12.200 8H14M3.800 3.800 5 5M11 11l1.200 1.200M3.800 12.200 5 11M11 5l1.200-1.200',
  info: 'M8 14A6 6 0 1 0 8 2a6 6 0 0 0 0 12ZM8 7.200v4M8 4.800v.300',
  ring: 'M8 13.500a5.500 5.500 0 1 0 0-11 5.500 5.500 0 0 0 0 11Z',
  link: 'M6.800 9.200 9.200 6.800M7.500 4.500l1-1a2.800 2.800 0 0 1 4 4l-1 1M8.500 11.500l-1 1a2.800 2.800 0 0 1-4-4l1-1',
  refresh: 'M13 8a5 5 0 1 1-1.500-3.500M13 2.500v2.500h-2.500',
  tag: 'M2.500 2.500h5l6 6-5 5-6-6ZM5.200 5.200h.100',
  globe: 'M8 14A6 6 0 1 0 8 2a6 6 0 0 0 0 12ZM2 8h12M8 2c2 2 2 10 0 12M8 2c-2 2-2 10 0 12',
  bolt: 'M9 1.500 3.500 9H8l-1 5.500L12.500 7H8Z',
  history: 'M2.500 8a5.500 5.500 0 1 0 1.700-4M2.500 2.500V5H5M8 5v3l2 1.500',
  compare: 'M2.500 3h4.500v10H2.500ZM9 3h4.500v10H9ZM4 6h1.500M10.500 6H12M10.500 8.500H12',
  dot: 'M8 8h.010',
};

export type IconName = keyof typeof P;

export function Icon({ name, size = 16, className, ...rest }: { name: string; size?: number } & SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 16 16" width={size} height={size} fill="none" stroke="currentColor" strokeWidth={1.5}
      strokeLinecap="square" strokeLinejoin="miter" aria-hidden="true" className={className} style={{ flex: 'none' }} {...rest}
    >
      <path d={P[name] ?? P.dot} />
    </svg>
  );
}
