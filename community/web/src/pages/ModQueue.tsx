import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuthStore } from "@/state/auth";
import { listReports, resolveReport, Report } from "@/api/reports";
import { timeAgo } from "@/lib/format";

type TabStatus = "pending" | "resolved" | "dismissed";

const TABS: { value: TabStatus; label: string }[] = [
  { value: "pending", label: "Pending" },
  { value: "resolved", label: "Resolved" },
  { value: "dismissed", label: "Dismissed" },
];

const REASON_COLORS: Record<string, string> = {
  spam: "text-red-600 bg-red-50",
  harassment: "text-red-600 bg-red-50",
  off_topic: "text-yellow-600 bg-yellow-50",
  misinformation: "text-orange-600 bg-orange-50",
  other: "text-gray-600 bg-gray-100",
};

const REASON_LABELS: Record<string, string> = {
  spam: "Spam",
  harassment: "Harassment",
  off_topic: "Off-topic",
  misinformation: "Misinformation",
  other: "Other",
};

export default function ModQueue() {
  const { role } = useAuthStore();
  const [status, setStatus] = useState<TabStatus>("pending");
  const [resolveNote, setResolveNote] = useState<{ [id: string]: string }>({});
  const qc = useQueryClient();

  if (!role || !["moderator", "admin"].includes(role)) {
    return <p className="text-center text-gray-400 py-12">Access denied.</p>;
  }

  const { data, isLoading } = useQuery({
    queryKey: ["reports", status],
    queryFn: () => listReports(status),
  });

  const resolveMutation = useMutation({
    mutationFn: ({ id, action, note }: { id: string; action: "resolve" | "dismiss"; note?: string }) =>
      resolveReport(id, action, note),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["reports", status] });
    },
  });

  return (
    <div className="max-w-3xl mx-auto">
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Mod Queue</h1>

      <div className="flex gap-2 mb-6">
        {TABS.map((tab) => (
          <button
            key={tab.value}
            onClick={() => setStatus(tab.value)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              status === tab.value
                ? "bg-brand text-white"
                : "border border-gray-300 text-gray-600 hover:border-gray-400"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {isLoading ? (
        <p className="text-center text-gray-400 py-12">Loading…</p>
      ) : !data || data.reports.length === 0 ? (
        <p className="text-center text-gray-400 py-12">No {status} reports.</p>
      ) : (
        <div className="space-y-4">
          {data.reports.map((report: Report) => (
            <ReportCard
              key={report.id}
              report={report}
              showActions={status === "pending"}
              note={resolveNote[report.id] ?? ""}
              onNoteChange={(val) => setResolveNote((prev) => ({ ...prev, [report.id]: val }))}
              onResolve={() => resolveMutation.mutate({ id: report.id, action: "resolve", note: resolveNote[report.id] || undefined })}
              onDismiss={() => resolveMutation.mutate({ id: report.id, action: "dismiss", note: resolveNote[report.id] || undefined })}
              isPending={resolveMutation.isPending}
            />
          ))}
        </div>
      )}
    </div>
  );
}

interface ReportCardProps {
  report: Report;
  showActions: boolean;
  note: string;
  onNoteChange: (val: string) => void;
  onResolve: () => void;
  onDismiss: () => void;
  isPending: boolean;
}

function ReportCard({ report, showActions, note, onNoteChange, onResolve, onDismiss, isPending }: ReportCardProps) {
  return (
    <div className="bg-white border border-gray-200 rounded-lg p-4 space-y-2">
      <div className="flex items-center">
        <span className="text-sm text-gray-700">
          Reported by <span className="font-medium">@{report.reporter_username}</span>
        </span>
        <span className="text-xs text-gray-400 ml-auto">{timeAgo(report.created_at)}</span>
      </div>

      <div className="text-sm">
        {report.post_id ? (
          <span>
            <Link
              to={`/posts/${report.post_slug}`}
              className="font-medium hover:text-brand transition-colors"
            >
              {report.post_title}
            </Link>
            {report.post_author_username && (
              <span className="text-gray-500"> by @{report.post_author_username}</span>
            )}
          </span>
        ) : (
          <span>
            <span className="text-gray-600 italic">"{report.comment_body}"</span>
            {report.comment_author_username && (
              <span className="text-gray-500"> in post by @{report.comment_author_username}</span>
            )}
          </span>
        )}
      </div>

      <div>
        <span
          className={`inline-block text-xs font-medium px-2 py-0.5 rounded-full ${
            REASON_COLORS[report.reason] ?? "text-gray-600 bg-gray-100"
          }`}
        >
          {REASON_LABELS[report.reason] ?? report.reason}
        </span>
      </div>

      {report.note && (
        <p className="text-xs text-gray-500">{report.note}</p>
      )}

      {showActions && (
        <div className="pt-1 space-y-2">
          <textarea
            placeholder="Moderator note (optional)"
            value={note}
            onChange={(e) => onNoteChange(e.target.value)}
            className="w-full px-2 py-1 text-xs border border-gray-200 rounded resize-none"
            rows={2}
          />
          <div className="flex gap-2">
            <button
              onClick={onResolve}
              disabled={isPending}
              className="text-sm px-3 py-1 bg-green-600 text-white rounded-lg disabled:opacity-50 hover:bg-green-700 transition-colors"
            >
              Resolve
            </button>
            <button
              onClick={onDismiss}
              disabled={isPending}
              className="text-sm px-3 py-1 border border-gray-300 rounded-lg disabled:opacity-50 hover:border-gray-400 transition-colors"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
