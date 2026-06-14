export default function Footer() {
  return (
    <footer style={{
      borderTop: '1px solid rgba(0,240,255,0.06)',
      padding: '3rem 2rem',
      textAlign: 'center',
      color: '#64748b',
      fontSize: '0.85rem',
      background: 'rgba(3,3,8,0.5)',
      backdropFilter: 'blur(8px)',
    }}>
      <p>
        <strong style={{
          background: 'linear-gradient(135deg, #00f0ff, #7c3aed)',
          WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
          fontWeight: 800,
        }}>SIN</strong>{' '}
        &mdash; Security Intelligence Network &mdash; Open-source cybersecurity &amp; compliance for the EU Digital Decade.
      </p>
      <p style={{ marginTop: '0.5rem' }}>
        Apache-2.0 &amp; AGPL-3.0 &middot;{' '}
        <a href="https://github.com/opensecstack/opensecstack">GitHub</a> &middot;{' '}
        <a href="https://github.com/opensecstack/opensecstack/blob/main/CONTRIBUTING.md">Contribute</a>
      </p>
    </footer>
  )
}
