interface Props {
  enabled: boolean
  onToggle: () => void
}

export default function HandTrackingToggle({ enabled, onToggle }: Props) {
  return (
    <button
      onClick={onToggle}
      title={enabled ? 'Disable hand tracking' : 'Enable hand tracking (webcam)'}
      style={{
        position: 'fixed',
        bottom: 24,
        right: 24,
        zIndex: 200,
        width: 48,
        height: 48,
        borderRadius: 14,
        border: `1px solid ${enabled ? '#10b981' : 'rgba(0,240,255,0.25)'}`,
        background: enabled ? 'rgba(16,185,129,0.15)' : 'rgba(5,5,16,0.85)',
        backdropFilter: 'blur(8px)',
        color: enabled ? '#10b981' : '#94a3b8',
        cursor: 'pointer',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: 22,
        transition: 'all 0.2s',
        boxShadow: enabled ? '0 0 20px rgba(16,185,129,0.3)' : 'none',
      }}
    >
      {enabled ? '🤚' : '✋'}
    </button>
  )
}
