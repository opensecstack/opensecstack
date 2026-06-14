interface Props {
  title: string
  description?: string
  action?: React.ReactNode
}

export default function PageHeader({ title, description, action }: Props) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 24 }}>
      <div>
        <h2 style={{ fontSize: 24, fontWeight: 700, margin: 0 }}>{title}</h2>
        {description && <p style={{ color: '#6b7280', fontSize: 14, marginTop: 4, marginBottom: 0 }}>{description}</p>}
      </div>
      {action}
    </div>
  )
}
