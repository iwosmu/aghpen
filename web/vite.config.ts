import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// The Go server serves web/dist and the API on one origin. In development
// the API is proxied to a local czujka (CZUJKA_DEV_API), or replaced by the
// dev-only fixture layer when VITE_FIXTURES=1.
export default defineConfig({
  plugins: [react(), tailwindcss()],
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
});
