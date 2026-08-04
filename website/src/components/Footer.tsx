import { useI18n } from '../i18n/useI18n'

export default function Footer() {
  const { t } = useI18n()

  return (
    <footer style={{
      borderTop: '1px solid var(--border)',
      padding: '3rem 2rem',
      textAlign: 'center',
      color: 'var(--text-muted)',
      fontSize: '0.85rem',
      background: 'var(--bg-card)',
      backdropFilter: 'blur(8px)',
    }}>
      <p>
        <strong style={{
          background: 'linear-gradient(135deg, #00f0ff, #7c3aed)',
          WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
          fontWeight: 800,
        }}>SIN</strong>{' '}
        &mdash; {t('footer.tagline')}
      </p>
      <p style={{ marginTop: '0.5rem' }}>
        Apache-2.0 &amp; AGPL-3.0 &middot;{' '}
        <a href="https://github.com/opensecstack/opensecstack">GitHub</a> &middot;{' '}
        <a href="https://github.com/opensecstack/opensecstack/blob/main/CONTRIBUTING.md">{t('footer.contribute')}</a>
      </p>
    </footer>
  )
}
