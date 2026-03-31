export default function Footer() {
  return (
    <footer style={{
      borderTop: '1px solid rgba(0,240,255,0.08)',
      padding: '3rem 2rem',
      textAlign: 'center',
      color: '#64748b',
      fontSize: '0.85rem',
    }}>
      <p>
        <strong style={{ color: '#00f0ff' }}>opensecstack</strong>{' '}
        &mdash; Open-source cybersecurity &amp; compliance for the EU Digital Decade.
      </p>
      <p style={{ marginTop: '0.5rem' }}>
        Apache-2.0 &amp; AGPL-3.0 &middot;{' '}
        <a href="https://github.com/opensecstack/opensecstack">GitHub</a> &middot;{' '}
        <a href="https://github.com/opensecstack/opensecstack/blob/main/CONTRIBUTING.md">Contribute</a>
      </p>
    </footer>
  )
}
