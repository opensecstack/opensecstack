import { useState, useEffect, useCallback, useRef } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, compliance, downloadAssessmentPDF } from '../api'
import type {
  Assessment,
  Control,
  Organisation,
  AssessmentStatus,
  ControlStatus,
  Artifact,
  ArtifactType,
  RemediationStatus,
  Role,
} from '../types'
import { hasRole } from '../auth'
import { StatusBadge } from '../components/StatusBadge'
import './Page.css'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TRANSITIONS: Partial<Record<AssessmentStatus, { label: string; to: AssessmentStatus }>> = {
  draft:        { label: 'Start Assessment', to: 'in_progress' },
  in_progress:  { label: 'Submit for Review', to: 'under_review' },
  under_review: { label: 'Mark Completed', to: 'completed' },
  completed:    { label: 'Archive', to: 'archived' },
}

const CONTROL_STATUSES: ControlStatus[] = [
  'not_assessed',
  'compliant',
  'partially_compliant',
  'non_compliant',
  'not_applicable',
]

const REMEDIATION_STATUSES: { value: RemediationStatus; label: string }[] = [
  { value: 'not_started', label: 'Not Started' },
  { value: 'in_progress', label: 'In Progress' },
  { value: 'blocked',     label: 'Blocked' },
  { value: 'completed',   label: 'Completed' },
]

const ARTIFACT_TYPES: ArtifactType[] = [
  'policy', 'procedure', 'evidence', 'report',
  'screenshot', 'log', 'certificate', 'contract',
]

const NIST_COLORS: Record<string, string> = {
  identify: '#6366f1',
  protect:  '#22c55e',
  detect:   '#eab308',
  respond:  '#f97316',
  recover:  '#3b82f6',
}

const REMEDIATION_STATUS_STYLES: Record<RemediationStatus, { bg: string; color: string }> = {
  not_started: { bg: '#64748b22', color: '#94a3b8' },
  in_progress: { bg: '#6366f122', color: '#818cf8' },
  blocked:     { bg: '#ef444422', color: '#f87171' },
  completed:   { bg: '#22c55e22', color: '#4ade80' },
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function NistBadge({ category }: { category: string }) {
  const color = NIST_COLORS[category] ?? '#94a3b8'
  return (
    <span style={{
      background: `${color}22`,
      color,
      border: `1px solid ${color}44`,
      borderRadius: 4,
      padding: '2px 8px',
      fontSize: 11,
      fontWeight: 600,
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
    }}>
      {category}
    </span>
  )
}

function RemediationStatusBadge({ status }: { status: RemediationStatus }) {
  const s = REMEDIATION_STATUS_STYLES[status]
  return (
    <span
      className="remediation-status-badge"
      style={{ background: s.bg, color: s.color, border: `1px solid ${s.color}44` }}
    >
      {status.replace(/_/g, ' ')}
    </span>
  )
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
  })
}

function isValidUrl(url: string): boolean {
  return /^https?:\/\/.+/.test(url.trim())
}

// Debounce hook
function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(t)
  }, [value, delay])
  return debounced
}

// ---------------------------------------------------------------------------
// ControlRow — main row + collapsible remediation panel
// ---------------------------------------------------------------------------

type PatchFn = (
  measureRef: string,
  data: Partial<{
    status: ControlStatus
    notes: string
    remediation_owner: string
    remediation_status: RemediationStatus
    external_ticket_url: string
    remediation_notes: string
  }>,
) => Promise<void>

interface ControlRowProps {
  control: Control
  onPatch: PatchFn
  colSpan: number
  role: Role
}

function ControlRow({ control, onPatch, colSpan, role }: ControlRowProps) {
  // --- main row state ---
  const [notes, setNotes] = useState(control.notes ?? '')
  const debouncedNotes = useDebounce(notes, 800)
  const [saving, setSaving] = useState(false)

  const initialNotes = control.notes ?? ''
  useEffect(() => {
    if (debouncedNotes === initialNotes) return
    setSaving(true)
    onPatch(control.measure_ref, { notes: debouncedNotes }).finally(() => setSaving(false))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedNotes])

  async function handleStatusChange(newStatus: ControlStatus) {
    setSaving(true)
    try {
      await onPatch(control.measure_ref, { status: newStatus })
    } finally {
      setSaving(false)
    }
  }

  // --- remediation panel state ---
  const [expanded, setExpanded] = useState(false)
  const [remOwner, setRemOwner] = useState(control.remediation_owner ?? '')
  const [remStatus, setRemStatus] = useState<RemediationStatus>(
    control.remediation_status ?? 'not_started',
  )
  const [ticketUrl, setTicketUrl] = useState(control.external_ticket_url ?? '')
  const [ticketUrlError, setTicketUrlError] = useState(false)
  const [remNotes, setRemNotes] = useState(control.remediation_notes ?? '')
  const debouncedRemNotes = useDebounce(remNotes, 800)
  const initialRemNotes = useRef(control.remediation_notes ?? '')

  useEffect(() => {
    if (debouncedRemNotes === initialRemNotes.current) return
    onPatch(control.measure_ref, { remediation_notes: debouncedRemNotes })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedRemNotes])

  async function handleRemOwnerBlur() {
    await onPatch(control.measure_ref, { remediation_owner: remOwner })
  }

  async function handleRemStatusChange(val: RemediationStatus) {
    setRemStatus(val)
    await onPatch(control.measure_ref, { remediation_status: val })
  }

  function handleTicketUrlBlur() {
    if (ticketUrl === '' || isValidUrl(ticketUrl)) {
      setTicketUrlError(false)
      onPatch(control.measure_ref, { external_ticket_url: ticketUrl })
    } else {
      setTicketUrlError(true)
    }
  }

  const needsAttention =
    remStatus === 'in_progress' || remStatus === 'blocked'

  const evidenceCount = Object.keys(control.evidence ?? {}).length

  return (
    <>
      <tr style={{ opacity: saving ? 0.7 : 1 }}>
        <td style={{ fontFamily: 'monospace', color: 'var(--text-muted)', fontSize: 12 }}>
          {control.article_ref}
        </td>
        <td style={{ fontWeight: 500, maxWidth: 220 }}>
          <span title={control.title}>{control.title}</span>
          {needsAttention && (
            <span
              title={`Remediation: ${remStatus.replace(/_/g, ' ')}`}
              style={{ marginLeft: 6, fontSize: 13 }}
            >
              🔧
            </span>
          )}
        </td>
        <td><NistBadge category={control.nist_category} /></td>
        <td>
          {hasRole(role, 'assessor') ? (
            <select
              className="inline-select"
              value={control.status}
              onChange={e => handleStatusChange(e.target.value as ControlStatus)}
              disabled={saving}
            >
              {CONTROL_STATUSES.map(s => (
                <option key={s} value={s}>
                  {s.replace(/_/g, ' ')}
                </option>
              ))}
            </select>
          ) : (
            <StatusBadge status={control.status} />
          )}
        </td>
        <td style={{ minWidth: 200 }}>
          {hasRole(role, 'assessor') ? (
            <input
              className="inline-input"
              value={notes}
              onChange={e => setNotes(e.target.value)}
              placeholder="Add notes..."
              disabled={saving}
            />
          ) : (
            <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>{notes || '—'}</span>
          )}
        </td>
        <td style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
          {evidenceCount > 0 ? (
            <span style={{ color: '#4ade80', fontWeight: 600 }}>{evidenceCount}</span>
          ) : (
            <span>—</span>
          )}
        </td>
        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
          <span style={{ color: 'var(--text-muted)', fontSize: 12, marginRight: 8 }}>
            {saving ? 'saving...' : ''}
          </span>
          <button
            className={`remediation-toggle${expanded ? ' active' : ''}`}
            onClick={() => setExpanded(v => !v)}
            title="Toggle remediation panel"
          >
            <span style={{ display: 'inline-block', transition: 'transform 0.15s', transform: expanded ? 'rotate(90deg)' : 'none' }}>▶</span>
            {' '}Remediation
            {remStatus !== 'not_started' && (
              <RemediationStatusBadge status={remStatus} />
            )}
          </button>
        </td>
      </tr>

      {expanded && (
        <tr className="remediation-row">
          <td colSpan={colSpan}>
            <div className="remediation-panel">
              <div className="remediation-field" style={{ minWidth: 180 }}>
                <label>Remediation Owner</label>
                <input
                  type="text"
                  value={remOwner}
                  onChange={e => setRemOwner(e.target.value)}
                  onBlur={handleRemOwnerBlur}
                  placeholder="e.g. Jane Smith"
                />
              </div>

              <div className="remediation-field" style={{ minWidth: 150 }}>
                <label>Remediation Status</label>
                <select
                  value={remStatus}
                  onChange={e => handleRemStatusChange(e.target.value as RemediationStatus)}
                >
                  {REMEDIATION_STATUSES.map(({ value, label }) => (
                    <option key={value} value={value}>{label}</option>
                  ))}
                </select>
              </div>

              <div className="remediation-field" style={{ minWidth: 240, flex: 1 }}>
                <label>Ticket URL {ticketUrlError && <span style={{ color: '#f87171', textTransform: 'none', fontWeight: 400 }}>(must start with http:// or https://)</span>}</label>
                <input
                  type="text"
                  className={ticketUrlError ? 'url-error' : ''}
                  value={ticketUrl}
                  onChange={e => { setTicketUrl(e.target.value); setTicketUrlError(false) }}
                  onBlur={handleTicketUrlBlur}
                  placeholder="https://jira.example.com/browse/NIS-123"
                />
              </div>

              <div className="remediation-field" style={{ minWidth: 280, flex: 2 }}>
                <label>Remediation Notes</label>
                <textarea
                  value={remNotes}
                  onChange={e => setRemNotes(e.target.value)}
                  placeholder="Describe the remediation plan..."
                  rows={3}
                />
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ---------------------------------------------------------------------------
// EvidenceSection
// ---------------------------------------------------------------------------

interface EvidenceSectionProps {
  assessmentId: string
  role: Role
}

function EvidenceSection({ assessmentId, role }: EvidenceSectionProps) {
  const [artifacts, setArtifacts] = useState<Artifact[]>([])
  const [loadingArtifacts, setLoadingArtifacts] = useState(true)
  const [artifactError, setArtifactError] = useState<string | null>(null)

  // Upload form
  const [showUpload, setShowUpload] = useState(false)
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [uploadType, setUploadType] = useState<ArtifactType>('evidence')
  const [uploadDesc, setUploadDesc] = useState('')
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)

  // Per-artifact action state
  const [downloading, setDownloading] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)
  const [signing, setSigning] = useState<string | null>(null)
  const [verifying, setVerifying] = useState<string | null>(null)
  const [artifactActionMsg, setArtifactActionMsg] = useState<{ id: string; msg: string } | null>(null)

  const loadArtifacts = useCallback(async () => {
    setLoadingArtifacts(true)
    setArtifactError(null)
    try {
      const data = await api.artifacts.list(assessmentId)
      setArtifacts(data)
    } catch (err: unknown) {
      setArtifactError(err instanceof Error ? err.message : 'Failed to load evidence files')
    } finally {
      setLoadingArtifacts(false)
    }
  }, [assessmentId])

  useEffect(() => {
    loadArtifacts()
  }, [loadArtifacts])

  async function handleUpload(e: React.FormEvent) {
    e.preventDefault()
    if (!uploadFile) return
    setUploading(true)
    setUploadError(null)
    try {
      await api.artifacts.upload(assessmentId, uploadFile, uploadType, uploadDesc || undefined)
      setShowUpload(false)
      setUploadFile(null)
      setUploadDesc('')
      setUploadType('evidence')
      await loadArtifacts()
    } catch (err: unknown) {
      setUploadError(err instanceof Error ? err.message : 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  async function handleDownload(artifact: Artifact) {
    setDownloading(artifact.id)
    try {
      const blob = await api.artifacts.download(artifact.id)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = artifact.filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err: unknown) {
      setArtifactError(err instanceof Error ? err.message : 'Download failed')
    } finally {
      setDownloading(null)
    }
  }

  async function handleDelete(artifact: Artifact) {
    if (!window.confirm('Delete this file?')) return
    setDeleting(artifact.id)
    try {
      await api.artifacts.delete(artifact.id)
      setArtifacts(prev => prev.filter(a => a.id !== artifact.id))
    } catch (err: unknown) {
      setArtifactError(err instanceof Error ? err.message : 'Delete failed')
    } finally {
      setDeleting(null)
    }
  }

  async function handleSign(artifact: Artifact) {
    setSigning(artifact.id)
    setArtifactActionMsg(null)
    try {
      await compliance.signArtifact(artifact.id)
      setArtifactActionMsg({ id: artifact.id, msg: 'Signed successfully' })
    } catch (err: unknown) {
      setArtifactError(err instanceof Error ? err.message : 'Sign failed')
    } finally {
      setSigning(null)
    }
  }

  async function handleVerify(artifact: Artifact) {
    setVerifying(artifact.id)
    setArtifactActionMsg(null)
    try {
      const result = await compliance.verifyArtifact(artifact.id)
      const msg = result?.valid === false ? 'Verification failed: signature invalid' : 'Signature verified'
      setArtifactActionMsg({ id: artifact.id, msg })
    } catch (err: unknown) {
      setArtifactError(err instanceof Error ? err.message : 'Verify failed')
    } finally {
      setVerifying(null)
    }
  }

  return (
    <div className="evidence-section">
      <div className="evidence-header">
        <h2>Evidence Files</h2>
        {hasRole(role, 'assessor') && (
          <button
            className="btn-secondary"
            onClick={() => setShowUpload(v => !v)}
          >
            {showUpload ? 'Cancel' : 'Upload File'}
          </button>
        )}
      </div>

      {showUpload && hasRole(role, 'assessor') && (
        <form className="upload-form" onSubmit={handleUpload}>
          <div className="upload-form-field">
            <label>File</label>
            <input
              type="file"
              required
              onChange={e => setUploadFile(e.target.files?.[0] ?? null)}
            />
          </div>
          <div className="upload-form-field">
            <label>Type</label>
            <select
              value={uploadType}
              onChange={e => setUploadType(e.target.value as ArtifactType)}
            >
              {ARTIFACT_TYPES.map(t => (
                <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>
              ))}
            </select>
          </div>
          <div className="upload-form-field" style={{ flex: 1, minWidth: 200 }}>
            <label>Description (optional)</label>
            <input
              type="text"
              value={uploadDesc}
              onChange={e => setUploadDesc(e.target.value)}
              placeholder="Brief description..."
            />
          </div>
          <button
            type="submit"
            className="btn-primary"
            disabled={uploading || !uploadFile}
          >
            {uploading ? 'Uploading...' : 'Upload'}
          </button>
          {uploadError && (
            <span style={{ color: '#f87171', fontSize: 13, alignSelf: 'center' }}>{uploadError}</span>
          )}
        </form>
      )}

      {artifactError && <p className="error">{artifactError}</p>}

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Filename</th>
              <th>Type</th>
              <th>Size</th>
              <th>Uploaded By</th>
              <th>Uploaded At</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {loadingArtifacts ? (
              <tr>
                <td colSpan={6} className="empty">Loading evidence files...</td>
              </tr>
            ) : artifacts.length === 0 ? (
              <tr>
                <td colSpan={6} className="empty">No evidence files uploaded yet.</td>
              </tr>
            ) : (
              artifacts.map(artifact => (
                <tr key={artifact.id} style={{ opacity: deleting === artifact.id ? 0.5 : 1 }}>
                  <td style={{ fontWeight: 500 }}>
                    {artifact.filename}
                    {artifact.description && (
                      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                        {artifact.description}
                      </div>
                    )}
                    {artifactActionMsg?.id === artifact.id && (
                      <div style={{ fontSize: 12, color: '#4ade80', marginTop: 2 }}>
                        {artifactActionMsg.msg}
                      </div>
                    )}
                  </td>
                  <td>
                    <span className="artifact-type-badge">{artifact.type}</span>
                  </td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 13 }}>
                    {formatBytes(artifact.size_bytes)}
                  </td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 13 }}>
                    {artifact.created_by}
                  </td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 13 }}>
                    {formatDate(artifact.created_at)}
                  </td>
                  <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                    {hasRole(role, 'auditor') && (
                      <button
                        className="btn-icon"
                        style={{ marginRight: 6 }}
                        onClick={() => handleSign(artifact)}
                        disabled={signing === artifact.id}
                      >
                        {signing === artifact.id ? 'Signing...' : 'Sign'}
                      </button>
                    )}
                    <button
                      className="btn-icon"
                      style={{ marginRight: 6 }}
                      onClick={() => handleVerify(artifact)}
                      disabled={verifying === artifact.id}
                    >
                      {verifying === artifact.id ? 'Verifying...' : 'Verify'}
                    </button>
                    <button
                      className="btn-icon"
                      style={{ marginRight: 6 }}
                      onClick={() => handleDownload(artifact)}
                      disabled={downloading === artifact.id}
                    >
                      {downloading === artifact.id ? 'Downloading...' : 'Download'}
                    </button>
                    <button
                      className="btn-danger"
                      onClick={() => handleDelete(artifact)}
                      disabled={deleting === artifact.id}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// AssessmentDetail (page)
// ---------------------------------------------------------------------------

export default function AssessmentDetail({ role }: { role: Role }) {
  const { id } = useParams<{ id: string }>()

  const [assessment, setAssessment] = useState<Assessment | null>(null)
  const [org, setOrg] = useState<Organisation | null>(null)
  const [controls, setControls] = useState<Control[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [transitioning, setTransitioning] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [reportError, setReportError] = useState<string | null>(null)
  const [downloadingPDF, setDownloadingPDF] = useState(false)
  const [pdfError, setPdfError] = useState<string | null>(null)

  // Editable metadata
  const [editing, setEditing] = useState(false)
  const [editTitle, setEditTitle] = useState('')
  const [editAssessor, setEditAssessor] = useState('')
  const [editDueDate, setEditDueDate] = useState('')
  const [editScope, setEditScope] = useState('')
  const [editSaving, setEditSaving] = useState(false)
  const [editError, setEditError] = useState<string | null>(null)

  // Approve / Reject
  const [approving, setApproving] = useState(false)
  const [rejectComment, setRejectComment] = useState('')
  const [showRejectInput, setShowRejectInput] = useState(false)
  const [approveError, setApproveError] = useState<string | null>(null)

  // Lock / Unlock
  const [locking, setLocking] = useState(false)
  const [isLocked, setIsLocked] = useState(false)
  const [lockError, setLockError] = useState<string | null>(null)

  // Compliance score
  const [score, setScore] = useState<number | null>(null)
  const [scoreFetching, setScoreFetching] = useState(false)
  const [scoreError, setScoreError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const asm = await api.assessments.get(id!)
      const ctls = await api.controls.list(id!)
      setAssessment(asm)
      setControls(ctls)
      const orgData = await api.organisations.get(asm.org_id)
      setOrg(orgData)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load assessment')
    } finally {
      setLoading(false)
    }
  }, [id])

  useEffect(() => {
    load()
  }, [load])

  function startEditMeta() {
    if (!assessment) return
    setEditTitle(assessment.title)
    setEditAssessor(assessment.assessor ?? '')
    setEditDueDate(assessment.due_date ?? '')
    setEditScope(assessment.scope ?? '')
    setEditError(null)
    setEditing(true)
  }

  async function handleSaveMeta(e: React.FormEvent) {
    e.preventDefault()
    if (!assessment || !editTitle.trim()) return
    setEditSaving(true)
    setEditError(null)
    try {
      const updated = await api.assessments.patch(assessment.id, {
        assessor: editAssessor.trim() || undefined,
        due_date: editDueDate || undefined,
        scope: editScope.trim() || undefined,
      })
      setAssessment(updated)
      setEditing(false)
    } catch (err: unknown) {
      setEditError(err instanceof Error ? err.message : 'Failed to update')
    } finally {
      setEditSaving(false)
    }
  }

  async function handleTransition() {
    if (!assessment) return
    const transition = TRANSITIONS[assessment.status]
    if (!transition) return
    setTransitioning(true)
    try {
      const updated = await api.assessments.patch(assessment.id, { status: transition.to })
      setAssessment(updated)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Status transition failed')
    } finally {
      setTransitioning(false)
    }
  }

  async function handleGenerateReport() {
    if (!assessment) return
    setGenerating(true)
    setReportError(null)
    try {
      const blob = await api.reports.generate(assessment.id)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const ext = blob.type === 'application/pdf' ? 'pdf' : 'bin'
      a.download = `nis2-assessment-${assessment.id.slice(0, 8)}.${ext}`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err: unknown) {
      setReportError(err instanceof Error ? err.message : 'Report generation failed')
    } finally {
      setGenerating(false)
    }
  }

  async function handleDownloadPDF() {
    if (!assessment) return
    setDownloadingPDF(true)
    setPdfError(null)
    try {
      const blob = await downloadAssessmentPDF(assessment.id)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `nis2-assessment-${assessment.id.slice(0, 8)}.pdf`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err: unknown) {
      setPdfError(err instanceof Error ? err.message : 'PDF download failed')
    } finally {
      setDownloadingPDF(false)
    }
  }

  const handlePatchControl = useCallback(
    async (
      measureRef: string,
      data: Partial<{
        status: ControlStatus
        notes: string
        remediation_owner: string
        remediation_status: RemediationStatus
        external_ticket_url: string
        remediation_notes: string
      }>,
    ) => {
      const updated = await api.controls.patch(id!, measureRef, data)
      setControls(prev => prev.map(c => (c.measure_ref === measureRef ? updated : c)))
      if (data.status) {
        const updatedAsm = await api.assessments.get(id!)
        setAssessment(updatedAsm)
      }
    },
    [id],
  )

  async function handleApprove() {
    setApproving(true)
    setApproveError(null)
    try {
      await compliance.approve(id!, 'approve')
      const updated = await api.assessments.get(id!)
      setAssessment(updated)
    } catch (err: unknown) {
      setApproveError(err instanceof Error ? err.message : 'Approve failed')
    } finally {
      setApproving(false)
    }
  }

  async function handleReject() {
    if (!rejectComment.trim()) {
      setShowRejectInput(true)
      return
    }
    setApproving(true)
    setApproveError(null)
    try {
      await compliance.approve(id!, 'reject', rejectComment.trim())
      const updated = await api.assessments.get(id!)
      setAssessment(updated)
      setShowRejectInput(false)
      setRejectComment('')
    } catch (err: unknown) {
      setApproveError(err instanceof Error ? err.message : 'Reject failed')
    } finally {
      setApproving(false)
    }
  }

  async function handleToggleLock() {
    setLocking(true)
    setLockError(null)
    try {
      if (isLocked) {
        await compliance.unlock(id!)
        setIsLocked(false)
      } else {
        await compliance.lock(id!)
        setIsLocked(true)
      }
    } catch (err: unknown) {
      setLockError(err instanceof Error ? err.message : 'Lock/unlock failed')
    } finally {
      setLocking(false)
    }
  }

  async function handleFetchScore() {
    setScoreFetching(true)
    setScoreError(null)
    try {
      await compliance.computeScore(id!)
      const result = await compliance.getScore(id!)
      const pct: number =
        typeof result?.score === 'number'
          ? result.score
          : typeof result?.percentage === 'number'
          ? result.percentage
          : typeof result?.compliance_score === 'number'
          ? result.compliance_score
          : null
      setScore(pct)
    } catch (err: unknown) {
      setScoreError(err instanceof Error ? err.message : 'Score calculation failed')
    } finally {
      setScoreFetching(false)
    }
  }

  if (loading) return <p className="loading">Loading assessment...</p>
  if (!assessment) return <p className="error">{error ?? 'Assessment not found'}</p>

  const summary = assessment.summary
  const transition = TRANSITIONS[assessment.status]

  // Total columns in the controls table (used for remediation row colSpan)
  const TABLE_COLS = 7

  function scoreColor(pct: number): string {
    if (pct >= 80) return '#4ade80'
    if (pct >= 50) return '#fcd34d'
    return '#f87171'
  }

  return (
    <div>
      <div className="breadcrumb">
        <Link to="/organisations">Organisations</Link>
        {org && (
          <>
            {' '}&rsaquo;{' '}
            <Link to={`/organisations/${org.id}`}>{org.name}</Link>
          </>
        )}
        {' '}&rsaquo; Assessment
      </div>

      {/* Header */}
      <div className="page-header" style={{ alignItems: 'flex-start', gap: 16, flexWrap: 'wrap' }}>
        <div>
          <h1 className="page-title" style={{ marginBottom: 6 }}>{assessment.title}</h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <StatusBadge status={assessment.status} />
            {assessment.assessor && (
              <span className="muted" style={{ fontSize: 13 }}>Assessor: {assessment.assessor}</span>
            )}
            {assessment.due_date && (
              <span className="muted" style={{ fontSize: 13 }}>Due: {assessment.due_date}</span>
            )}
            {hasRole(role, 'assessor') && (
              <button className="btn-icon" onClick={startEditMeta} style={{ marginLeft: 4, padding: '2px 8px', fontSize: 12 }}>
                Edit
              </button>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, marginLeft: 'auto', flexWrap: 'wrap' }}>
          {transition && (
            <button
              className="btn-primary"
              onClick={handleTransition}
              disabled={transitioning}
            >
              {transitioning ? 'Updating...' : transition.label}
            </button>
          )}
          {hasRole(role, 'admin') && (
            <button
              className={isLocked ? 'btn-secondary' : 'btn-icon'}
              onClick={handleToggleLock}
              disabled={locking}
              style={isLocked ? { borderColor: '#fcd34d44', color: '#fcd34d' } : {}}
            >
              {locking ? '...' : isLocked ? 'Unlock' : 'Lock'}
            </button>
          )}
          <button
            className="btn-secondary"
            onClick={handleGenerateReport}
            disabled={generating}
          >
            {generating ? 'Generating...' : 'Generate Report'}
          </button>
          <button
            className="btn-secondary"
            onClick={handleDownloadPDF}
            disabled={downloadingPDF}
          >
            {downloadingPDF ? 'Downloading...' : 'Download PDF Report'}
          </button>
          <Link
            to={`/assessments/${id}/gaps`}
            className="btn-secondary"
            style={{ display: 'inline-flex', alignItems: 'center' }}
          >
            View Gap Analysis
          </Link>
        </div>
      </div>

      {/* Edit metadata panel */}
      {editing && hasRole(role, 'assessor') && (
        <div className="card form-card" style={{ marginBottom: 16 }}>
          <h3>Edit Assessment</h3>
          {editError && <p className="error">{editError}</p>}
          <form onSubmit={handleSaveMeta}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 24px' }}>
              <div className="form-row">
                <label>Assessor</label>
                <input value={editAssessor} onChange={e => setEditAssessor(e.target.value)} placeholder="j.smith@example.com" disabled={editSaving} />
              </div>
              <div className="form-row">
                <label>Due Date</label>
                <input type="date" value={editDueDate} onChange={e => setEditDueDate(e.target.value)} disabled={editSaving} />
              </div>
              <div className="form-row" style={{ gridColumn: '1 / -1' }}>
                <label>Scope</label>
                <input value={editScope} onChange={e => setEditScope(e.target.value)} placeholder="All NIS and information systems in scope..." disabled={editSaving} />
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn-primary" type="submit" disabled={editSaving}>
                {editSaving ? 'Saving...' : 'Save Changes'}
              </button>
              <button className="btn-secondary" type="button" onClick={() => setEditing(false)} disabled={editSaving}>
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {error && <p className="error">{error}</p>}
      {reportError && <p className="error">Report: {reportError}</p>}
      {pdfError && <p className="error">PDF: {pdfError}</p>}
      {lockError && <p className="error">Lock: {lockError}</p>}

      {/* Approve / Reject panel — only shown when status is submitted / under_review and user is admin */}
      {assessment.status === 'under_review' && hasRole(role, 'admin') && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontWeight: 600, fontSize: 14, marginRight: 4 }}>Review Decision</span>
            <button
              className="btn-primary"
              onClick={handleApprove}
              disabled={approving}
            >
              {approving ? 'Processing...' : 'Approve'}
            </button>
            <button
              className="btn-danger"
              style={{ padding: '8px 16px', fontSize: 14 }}
              onClick={() => setShowRejectInput(v => !v)}
              disabled={approving}
            >
              Reject
            </button>
          </div>
          {showRejectInput && (
            <div style={{ marginTop: 12, display: 'flex', gap: 8, alignItems: 'flex-end', flexWrap: 'wrap' }}>
              <div className="form-row" style={{ flex: 1, minWidth: 260, marginBottom: 0 }}>
                <label>Rejection Comment *</label>
                <input
                  value={rejectComment}
                  onChange={e => setRejectComment(e.target.value)}
                  placeholder="Reason for rejection..."
                  disabled={approving}
                />
              </div>
              <button
                className="btn-danger"
                style={{ padding: '8px 16px', fontSize: 14 }}
                onClick={handleReject}
                disabled={approving || !rejectComment.trim()}
              >
                {approving ? 'Rejecting...' : 'Confirm Reject'}
              </button>
              <button
                className="btn-secondary"
                onClick={() => { setShowRejectInput(false); setRejectComment('') }}
                disabled={approving}
              >
                Cancel
              </button>
            </div>
          )}
          {approveError && <p className="error" style={{ marginTop: 8, marginBottom: 0 }}>{approveError}</p>}
        </div>
      )}

      {/* Compliance Score panel */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
          <span style={{ fontWeight: 600, fontSize: 14 }}>Compliance Score</span>
          {score !== null && (
            <span
              style={{
                fontSize: 28,
                fontWeight: 700,
                color: scoreColor(score),
                lineHeight: 1,
              }}
            >
              {score.toFixed(1)}%
            </span>
          )}
          {hasRole(role, 'assessor') && (
            <button
              className="btn-secondary"
              onClick={handleFetchScore}
              disabled={scoreFetching}
            >
              {scoreFetching ? 'Calculating...' : score !== null ? 'Recalculate' : 'Calculate Score'}
            </button>
          )}
          {score !== null && (
            <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>
              {score >= 80 ? 'Good standing' : score >= 50 ? 'Needs improvement' : 'Critical attention required'}
            </span>
          )}
        </div>
        {scoreError && <p className="error" style={{ marginTop: 8, marginBottom: 0 }}>{scoreError}</p>}
      </div>

      {/* Summary stats */}
      {summary && (
        <div className="stats-grid">
          <div className="stat-card compliant">
            <div className="stat-value" style={{ color: '#4ade80' }}>{summary.compliant}</div>
            <div className="stat-label">Compliant</div>
          </div>
          <div className="stat-card partial">
            <div className="stat-value" style={{ color: '#fcd34d' }}>{summary.partially_compliant}</div>
            <div className="stat-label">Partial</div>
          </div>
          <div className="stat-card non-compliant">
            <div className="stat-value" style={{ color: '#f87171' }}>{summary.non_compliant}</div>
            <div className="stat-label">Non-Compliant</div>
          </div>
          <div className="stat-card not-assessed">
            <div className="stat-value" style={{ color: '#94a3b8' }}>{summary.not_assessed}</div>
            <div className="stat-label">Not Assessed</div>
          </div>
          {summary.overall_risk_score != null && (
            <div className="stat-card">
              <div className="stat-value" style={{ color: '#f97316' }}>
                {summary.overall_risk_score.toFixed(1)}
              </div>
              <div className="stat-label">Risk Score</div>
            </div>
          )}
        </div>
      )}

      {/* Controls table */}
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Ref</th>
              <th>Title</th>
              <th>NIST Category</th>
              <th>Status</th>
              <th>Notes</th>
              <th style={{ textAlign: 'center' }}>Evidence</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {controls.length === 0 ? (
              <tr>
                <td colSpan={TABLE_COLS} className="empty">No controls found.</td>
              </tr>
            ) : (
              controls
                .sort((a, b) => a.measure_ref.localeCompare(b.measure_ref))
                .map(control => (
                  <ControlRow
                    key={control.id}
                    control={control}
                    onPatch={handlePatchControl}
                    colSpan={TABLE_COLS}
                    role={role}
                  />
                ))
            )}
          </tbody>
        </table>
      </div>

      {/* Evidence section */}
      <EvidenceSection assessmentId={id!} role={role} />

      {/* Scope / metadata card */}
      {(assessment.scope || assessment.framework_version) && (
        <div className="card" style={{ marginTop: 24 }}>
          <div style={{ display: 'flex', gap: 32, flexWrap: 'wrap' }}>
            {assessment.framework_version && (
              <div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                  Framework
                </div>
                <div style={{ fontFamily: 'monospace', fontSize: 13 }}>{assessment.framework_version}</div>
              </div>
            )}
            {assessment.scope && (
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                  Scope
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.6 }}>{assessment.scope}</div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
