import { Link } from 'react-router';
import { t } from '../i18n';
import { useSession } from '../session';

/** The next step for a list that is empty because the installation has no scan data yet. */
export function NextSteps() {
  const { can } = useSession();
  return (
    <span className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
      <Link className="link" to="/runs">{t('Przejdź do skanów', 'Go to scans')}</Link>
      {can('results:create') ? <Link className="link" to="/transfer">{t('Zaimportuj wyniki', 'Import results')}</Link> : null}
    </span>
  );
}
