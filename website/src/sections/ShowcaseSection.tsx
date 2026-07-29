import ScrollSection from '../components/ScrollSection'
import MediaVideo from '../components/MediaVideo'
import { showcaseMedia } from '../data/media'

export default function ShowcaseSection() {
  // No clips configured yet → render nothing (no empty section).
  if (showcaseMedia.length === 0) return null

  return (
    <ScrollSection id="showcase">
      <h2 className="section-title"><span className="gradient-text">In</span> Motion</h2>
      <p className="section-subtitle">
        Generative sequences produced with Higgsfield AI &mdash; the ecosystem,
        animated.
      </p>
      <div className="grid-2">
        {showcaseMedia.map(clip => (
          <figure
            key={clip.name}
            className="glass-card"
            style={{ padding: '1rem', margin: 0 }}
          >
            <MediaVideo
              name={clip.name}
              variant="content"
              style={{ width: '100%', borderRadius: 12, display: 'block' }}
            />
            {(clip.title || clip.caption) && (
              <figcaption style={{ marginTop: '1rem' }}>
                {clip.title && (
                  <div style={{ fontWeight: 700, fontSize: '1.05rem' }}>{clip.title}</div>
                )}
                {clip.caption && (
                  <div style={{ color: '#8892a8', fontSize: '0.88rem', lineHeight: 1.6, marginTop: '0.35rem' }}>
                    {clip.caption}
                  </div>
                )}
              </figcaption>
            )}
          </figure>
        ))}
      </div>
    </ScrollSection>
  )
}
