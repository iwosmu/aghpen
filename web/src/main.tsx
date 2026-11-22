import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import App from './App';
import { installStaleBuildReload } from './lib/staleBuild';

installStaleBuildReload();

async function boot() {
  // Dev-only fixture layer. __CZUJKA_FIXTURES__ is a compile-time constant that
  // is false in every build (vite.config.ts), so the production bundle contains
  // neither this branch nor the fixtures chunk.
  if (__CZUJKA_FIXTURES__) {
    const fx = await import('./fixtures');
    fx.install();
  }
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}

boot();
