import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// The Go server serves web/dist and the API on one origin. In development
// the API is proxied to a local czujka (CZUJKA_DEV_API), or replaced by the
// dev-only fixture layer when VITE_FIXTURES=1.
//
// The fixture layer exists only in the dev server. __CZUJKA_FIXTURES__ is a
// compile-time constant: it is always false in a build, so the bundler drops
// the import of src/fixtures. A build with VITE_FIXTURES=1 is refused, and
// scripts/check-bundle.mjs fails the build when fixture markers reach dist.
export default defineConfig(({ command }) => {
  const wantFixtures = process.env.VITE_FIXTURES === '1';
  if (command === 'build' && wantFixtures) {
    throw new Error('VITE_FIXTURES=1 is a development switch. A build never contains the fixture layer: unset VITE_FIXTURES and build again.');
  }
  return {
    plugins: [react(), tailwindcss()],
    define: { __CZUJKA_FIXTURES__: JSON.stringify(command === 'serve' && wantFixtures) },
    server: {
      host: '127.0.0.1',
      port: 5173,
      proxy: {
        '/api': { target: process.env.CZUJKA_DEV_API ?? 'http://127.0.0.1:8080', changeOrigin: false },
      },
    },
    build: {
      outDir: 'dist',
      sourcemap: false,
      target: 'es2022',
    },
  };
});
