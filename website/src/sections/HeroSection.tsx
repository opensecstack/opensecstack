import { motion } from 'framer-motion'
import { useI18n } from '../i18n/useI18n'
import MediaVideo from '../components/MediaVideo'
import { heroMedia } from '../data/media'

export default function HeroSection() {
  const { t } = useI18n()

  return (
    <section
      className="section"
      id="hero"
      style={{ display: 'flex', alignItems: 'center', minHeight: '100vh', position: 'relative', overflow: 'hidden' }}
    >
      {heroMedia && (
        <MediaVideo
          name={heroMedia}
          variant="background"
          style={{
            position: 'absolute', inset: 0, width: '100%', height: '100%',
            objectFit: 'cover', zIndex: 0, opacity: 0.35, pointerEvents: 'none',
          }}
        />
      )}
      <motion.div
        initial={{ opacity: 0, y: 50 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 1, ease: 'easeOut' }}
        style={{ maxWidth: 700, position: 'relative', zIndex: 1 }}
      >
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3, duration: 0.6 }}
          style={{
            display: 'inline-block', padding: '5px 14px', borderRadius: 8, marginBottom: '1.5rem',
            background: 'rgba(0,240,255,0.06)', border: '1px solid rgba(0,240,255,0.15)',
            fontSize: '0.8rem', fontFamily: 'var(--mono)', color: 'var(--accent)', letterSpacing: '0.08em',
          }}
        >
          {t('hero.badge')}
        </motion.div>

        <h1 style={{
          fontSize: 'clamp(2.8rem, 7vw, 5rem)', fontWeight: 800,
          letterSpacing: '-0.04em', lineHeight: 1.05,
          textShadow: '0 0 60px rgba(0,240,255,0.1)',
        }}>
          <span className="gradient-text">{t('hero.title.line1')}</span><br />
          {t('hero.title.line2')}<br />
          {t('hero.title.line3')}
        </h1>

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6, duration: 0.8 }}
          style={{
            marginTop: '1.8rem', fontSize: '1.15rem', color: 'var(--text-muted)',
            lineHeight: 1.7, maxWidth: 520,
          }}
        >
          {t('hero.subtitle')}<br />
          {t('hero.subtitle2')}
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.9, duration: 0.6 }}
          className="stat-grid"
          style={{ marginTop: '2.5rem' }}
        >
          {[
            { v: '10/10', l: t('hero.stat.owasp') },
            { v: '10', l: t('hero.stat.nis2') },
            { v: '5', l: t('hero.stat.marshal') },
            { v: '4', l: t('hero.stat.sdks') },
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
          style={{ marginTop: '2.5rem', display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center' }}
        >
          <a href="https://github.com/opensecstack/opensecstack" target="_blank" rel="noopener noreferrer" style={{
            padding: '13px 30px', borderRadius: 11, fontWeight: 700, fontSize: '0.95rem',
            background: 'linear-gradient(135deg, #00f0ff, #7c3aed)', color: '#030308',
            textDecoration: 'none', boxShadow: '0 0 30px rgba(0,240,255,0.2)',
            transition: 'box-shadow 0.3s',
          }}>
            {t('hero.cta.github')}
          </a>
          <a href="#platforms" style={{
            padding: '13px 30px', borderRadius: 11, fontWeight: 600, fontSize: '0.95rem',
            border: '1px solid rgba(0,240,255,0.25)', color: 'var(--accent)',
            textDecoration: 'none', backdropFilter: 'blur(8px)',
            transition: 'border-color 0.3s, box-shadow 0.3s',
          }}>
            {t('hero.cta.platforms')}
          </a>
        </motion.div>
      </motion.div>
    </section>
  )
}
