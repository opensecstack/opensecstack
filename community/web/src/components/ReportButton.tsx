import { useState } from "react";
import { Flag } from "lucide-react";
import { useAuthStore } from "@/state/auth";
import { reportPost, reportComment, ReportReason } from "@/api/reports";
import axios from "axios";

interface Props {
  postId?: string;
  commentId?: string;
}

const REASON_LABELS: { value: ReportReason; label: string }[] = [
  { value: "spam", label: "Spam" },
  { value: "harassment", label: "Harassment" },
  { value: "off_topic", label: "Off-topic" },
  { value: "misinformation", label: "Misinformation" },
  { value: "other", label: "Other" },
];

export default function ReportButton({ postId, commentId }: Props) {
  const { token } = useAuthStore();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState<ReportReason>("spam");
  const [note, setNote] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!token) return null;

  function openModal() {
    setOpen(true);
    setSubmitted(false);
    setError(null);
    setReason("spam");
    setNote("");
  }

  function closeModal() {
    setOpen(false);
    setError(null);
    setSubmitted(false);
  }

  async function handleSubmit() {
    setSubmitting(true);
    setError(null);
    try {
      if (postId) {
        await reportPost(postId, reason, note);
      } else if (commentId) {
        await reportComment(commentId, reason, note);
      }
      setSubmitted(true);
      setTimeout(() => {
        setOpen(false);
        setSubmitted(false);
      }, 1500);
    } catch (err) {
      if (axios.isAxiosError(err) && err.response?.status === 409) {
        setError("already_reported");
      } else {
        setError("failed");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <button
        onClick={openModal}
        className="text-gray-400 hover:text-gray-600 transition-colors"
        aria-label="Report content"
      >
        <Flag className="w-4 h-4" />
      </button>

      {open && (
        <div
          className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center"
          onClick={closeModal}
        >
          <div
            className="bg-white rounded-xl shadow-lg p-6 max-w-sm w-full mx-4"
            onClick={(e) => e.stopPropagation()}
          >
            <p className="font-semibold mb-4">Report content</p>

            {submitted ? (
              <p className="text-green-600 text-sm text-center py-2">
                ✓ Report submitted
              </p>
            ) : (
              <>
                {error === "already_reported" && (
                  <p className="text-red-500 text-sm mb-3">You already reported this.</p>
                )}
                {error && error !== "already_reported" && (
                  <p className="text-red-500 text-sm mb-3">Failed to submit. Try again.</p>
                )}

                <select
                  value={reason}
                  onChange={(e) => setReason(e.target.value as ReportReason)}
                  className="w-full border rounded-lg px-3 py-2 text-sm mb-3"
                >
                  {REASON_LABELS.map(({ value, label }) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>

                <textarea
                  rows={2}
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  placeholder="Additional details (optional)"
                  className="w-full border rounded-lg px-3 py-2 text-sm mb-4 resize-none"
                />

                <div className="flex gap-2">
                  <button
                    onClick={handleSubmit}
                    disabled={submitting}
                    className="flex-1 bg-brand text-white px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50"
                  >
                    {submitting ? "Submitting…" : "Submit"}
                  </button>
                  <button
                    onClick={closeModal}
                    disabled={submitting}
                    className="flex-1 border border-gray-300 px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50"
                  >
                    Cancel
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
}
