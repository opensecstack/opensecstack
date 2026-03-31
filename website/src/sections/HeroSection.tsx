import { motion } from 'framer-motion'

export default function HeroSection() {
  return (
    <section className="section" id="hero" style={{ display: 'flex', alignItems: 'center', minHeight: '100vh' }}>
      <motion.div
        initial={{ opacity: 0, y: 50 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 1, ease: 'easeOut' }}
        style={{ maxWidth: 700 }}
      >
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3, duration: 0.6 }}
          style={{
            display: 'inline-block', padding: '5px 14px', borderRadius: 8, marginBottom: '1.5rem',
            background: 'rgba(0,240,255,0.06)', border: '1px solid rgba(0,240,255,0.15)',
            fontSize: '0.8rem', fontFamily: 'var(--mono)', color: '#00f0ff', letterSpacing: '0.08em',
          }}
        >
          EU Digital Decade Compliance
        </motion.div>

        <h1 style={{
          fontSize: 'clamp(2.8rem, 7vw, 5rem)', fontWeight: 800,
          letterSpacing: '-0.04em', lineHeight: 1.05,
          textShadow: '0 0 60px rgba(0,240,255,0.1)',
        }}>
          <span className="gradient-text">Open-Source</span><br />
          Security &amp;<br />
          Compliance
        </h1>

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6, duration: 0.8 }}
          style={{
            marginTop: '1.8rem', fontSize: '1.15rem', color: '#8892a8',
            lineHeight: 1.7, maxWidth: 520,
          }}
        >
          8 platforms. 3 SDKs. 1 immutable governance chain.<br />
          Built for the EU Digital Decade.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.9, duration: 0.6 }}
          className="stat-grid"
          style={{ marginTop: '2.5rem' }}
        >
          {[
            { v: '10/10', l: 'OWASP API Top 10' },
            { v: '10', l: 'NIS2 Controls' },
            { v: '5', l: 'MARSHAL Gates' },
            { v: '4', l: 'SDKs' },
          ].map(s => (
            <div className="stat-item" key={s.l}>
              <div className="stat-value">{s.v}</div>
              <div className="stat-label">{s.l}</div>
            </div>
          ))}
        </motion.div>

        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.2, duration: 0.6 }}
          style={{ marginTop: '2.5rem', display: 'flex', gap: '1rem', flexWrap: 'wrap' }}
        >
          <a href="#platforms" style={{
            padding: '13px 30px', borderRadius: 11, fontWeight: 700, fontSize: '0.95rem',
            background: 'linear-gradient(135deg, #00f0ff, #7c3aed)', color: '#030308',
            textDecoration: 'none', boxShadow: '0 0 30px rgba(0,240,255,0.2)',
            transition: 'box-shadow 0.3s',
          }}>
            Explore Platforms
          </a>
          <a href="https://github.com/opensecstack/opensecstack" target="_blank" rel="noopener noreferrer" style={{
            padding: '13px 30px', borderRadius: 11, fontWeight: 600, fontSize: '0.95rem',
            border: '1px solid rgba(0,240,255,0.25)', color: '#00f0ff',
            textDecoration: 'none', backdropFilter: 'blur(8px)',
            transition: 'border-color 0.3s, box-shadow 0.3s',
          }}>
            View on GitHub
          </a>
        </motion.div>
      </motion.div>
    </section>
  )
}
