import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import App from './App';

async function boot() {
  // Dev-only fixture layer. The condition is a build-time constant, so the
  // production bundle contains neither this branch nor the fixtures chunk.
  if (import.meta.env.DEV && import.meta.env.VITE_FIXTURES === '1') {
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
