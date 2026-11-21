import { Component, type ErrorInfo, type ReactNode } from 'react';
import { t } from '../i18n';
import { Icon } from './Icon';

/** Keeps a rendering fault of one page inside that page: the navigation and the emergency stop stay usable. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('page render failed', error, info.componentStack);
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div role="alert" data-testid="page-crash" className="flex flex-col items-start gap-1.5 px-4 py-8 sm:px-6">
        <Icon name="alert" className="text-danger" size={18} />
        <p className="text-sm font-medium text-ink">{t('Tej strony nie udało się wyświetlić', 'This page could not be shown')}</p>
        <p className="mono max-w-[90ch] break-words text-xs text-ink-3">{error.message}</p>
        <button type="button" className="link mt-2 text-sm" onClick={() => this.setState({ error: null })}>{t('Spróbuj ponownie', 'Try again')}</button>
      </div>
    );
  }
}
