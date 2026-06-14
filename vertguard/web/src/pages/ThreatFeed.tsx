import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { CheckCircle, XCircle, AlertTriangle, Search } from "lucide-react";
import { api } from "../lib/api";

// ─── Type helpers ────────────────────────────────────────────────────────────

interface IOC {
  value: string;
  type: string;
  severity: string;
  source: string;
  first_seen: string;
  last_seen: string;
}

interface AtlasEntry {
  tactic: string;
  technique_id: string;
  technique_name: string;
  covered: boolean;
}

// ─── Small shared primitives ─────────────────────────────────────────────────

function SkeletonRow({ cols }: { cols: number }) {
  return (
    <tr className="border-t border-slate-800 animate-pulse">
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="py-2 pr-3">
          <div className="h-3 bg-slate-700 rounded w-3/4" />
        </td>
      ))}
    </tr>
  );
}

function EmptyState({ label }: { label: string }) {
  return (
    <tr>
      <td colSpan={99} className="py-10 text-center text-slate-500 text-sm">
        {label}
      </td>
    </tr>
  );
}

function ErrorState({ message }: { message: string }) {
  return (
    <div className="flex items-center gap-2 text-rose-400 text-sm mt-4">
      <AlertTriangle size={16} />
      <span>{message}</span>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const s = severity?.toLowerCase() ?? "";
  const classes =
    s === "critical"
      ? "bg-rose-900/60 text-rose-300 border-rose-700"
      : s === "high"
        ? "bg-orange-900/60 text-orange-300 border-orange-700"
        : s === "medium"
          ? "bg-yellow-900/60 text-yellow-300 border-yellow-700"
          : "bg-slate-800 text-slate-400 border-slate-700";
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs border font-medium ${classes}`}>
      {severity || "—"}
    </span>
  );
}

function CoveredBadge({ covered }: { covered: boolean }) {
  return covered ? (
    <span className="inline-flex items-center gap-1 text-emerald-400 text-xs font-medium">
      <CheckCircle size={13} /> Yes
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-slate-500 text-xs font-medium">
      <XCircle size={13} /> No
    </span>
  );
}

// ─── IOC Feed tab ─────────────────────────────────────────────────────────────

function IOCFeedTab() {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");

  const { data, isLoading, error } = useQuery<IOC[]>({
    queryKey: ["iocs"],
    queryFn: api.iocs,
  });

  const rows: IOC[] = Array.isArray(data) ? data : [];
  const filtered = search.trim()
    ? rows.filter((r) => r.value?.toLowerCase().includes(search.trim().toLowerCase()))
    : rows;

  return (
    <div>
      {/* toolbar */}
      <div className="flex items-center gap-3 mb-4">
        <div className="relative flex-1 max-w-xs">
          <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t("threatfeed:ioc.search_placeholder")}
            className="w-full bg-slate-900 border border-slate-700 rounded pl-8 pr-3 py-1.5 text-sm focus:outline-none focus:border-indigo-500"
          />
        </div>
        {!isLoading && !error && (
          <span className="bg-slate-800 border border-slate-700 text-slate-300 text-xs font-medium px-2.5 py-1 rounded-full">
            {filtered.length} {t("threatfeed:ioc.count_label")}
          </span>
        )}
      </div>

      {error && (
        <ErrorState message={t("threatfeed:errors.load_failed", { detail: String(error) })} />
      )}

      <div className="bg-slate-900 border border-slate-800 rounded overflow-x-auto">
        <table className="w-full text-xs">
          <thead className="text-slate-500 border-b border-slate-800">
            <tr>
              <th className="text-left px-3 py-2">{t("threatfeed:ioc.col.value")}</th>
              <th className="text-left px-3 py-2">{t("threatfeed:ioc.col.type")}</th>
              <th className="text-left px-3 py-2">{t("threatfeed:ioc.col.severity")}</th>
              <th className="text-left px-3 py-2">{t("threatfeed:ioc.col.source")}</th>
              <th className="text-left px-3 py-2">{t("threatfeed:ioc.col.first_seen")}</th>
              <th className="text-left px-3 py-2">{t("threatfeed:ioc.col.last_seen")}</th>
            </tr>
          </thead>
          <tbody>
            {isLoading &&
              Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={i} cols={6} />)}

            {!isLoading && !error && filtered.length === 0 && (
              <EmptyState label={t("threatfeed:ioc.empty")} />
            )}

            {!isLoading &&
              !error &&
              filtered.map((row, i) => (
                <tr key={i} className="border-t border-slate-800 hover:bg-slate-800/40">
                  <td className="px-3 py-2 font-mono text-slate-200 max-w-[220px] truncate">
                    {row.value || "—"}
                  </td>
                  <td className="px-3 py-2 text-slate-400 uppercase tracking-wide">
                    {row.type || "—"}
                  </td>
                  <td className="px-3 py-2">
                    <SeverityBadge severity={row.severity} />
                  </td>
                  <td className="px-3 py-2 text-slate-400">{row.source || "—"}</td>
                  <td className="px-3 py-2 text-slate-500">{row.first_seen || "—"}</td>
                  <td className="px-3 py-2 text-slate-500">{row.last_seen || "—"}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── ATLAS Coverage tab ───────────────────────────────────────────────────────

function AtlasCoverageTab() {
  const { t } = useTranslation();
  const [onlyCovered, setOnlyCovered] = useState(false);

  const { data, isLoading, error } = useQuery<AtlasEntry[]>({
    queryKey: ["atlas-coverage"],
    queryFn: api.atlasCoverage,
  });

  const rows: AtlasEntry[] = Array.isArray(data) ? data : [];
  const visible = onlyCovered ? rows.filter((r) => r.covered) : rows;

  // Coverage summary
  const total = rows.length;
  const covered = rows.filter((r) => r.covered).length;
  const pct = total > 0 ? Math.round((covered / total) * 100) : 0;

  // Group by tactic
  const grouped = visible.reduce<Record<string, AtlasEntry[]>>((acc, entry) => {
    const tactic = entry.tactic || "Unknown";
    if (!acc[tactic]) acc[tactic] = [];
    acc[tactic].push(entry);
    return acc;
  }, {});
  const tactics = Object.keys(grouped).sort();

  return (
    <div>
      {/* Coverage summary bar */}
      {!isLoading && !error && total > 0 && (
        <div className="mb-4 bg-slate-900 border border-slate-800 rounded p-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-slate-300">
              {t("threatfeed:atlas.coverage_summary", { covered, total, pct })}
            </span>
            <button
              onClick={() => setOnlyCovered((v) => !v)}
              className={`text-xs px-3 py-1 rounded border transition-colors ${
                onlyCovered
                  ? "bg-indigo-500/20 border-indigo-500 text-indigo-300"
                  : "bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200"
              }`}
            >
              {onlyCovered
                ? t("threatfeed:atlas.show_all")
                : t("threatfeed:atlas.show_covered_only")}
            </button>
          </div>
          {/* Progress bar */}
          <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-indigo-500 rounded-full transition-all"
              style={{ width: `${pct}%` }}
            />
          </div>
        </div>
      )}

      {error && (
        <ErrorState message={t("threatfeed:errors.load_failed", { detail: String(error) })} />
      )}

      <div className="bg-slate-900 border border-slate-800 rounded overflow-x-auto">
        <table className="w-full text-xs">
          <thead className="text-slate-500 border-b border-slate-800">
            <tr>
              <th className="text-left px-3 py-2">{t("threatfeed:atlas.col.tactic")}</th>
              <th className="text-left px-3 py-2">{t("threatfeed:atlas.col.technique_id")}</th>
              <th className="text-left px-3 py-2">{t("threatfeed:atlas.col.technique_name")}</th>
              <th className="text-left px-3 py-2">{t("threatfeed:atlas.col.covered")}</th>
            </tr>
          </thead>
          <tbody>
            {isLoading &&
              Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} cols={4} />)}

            {!isLoading && !error && visible.length === 0 && (
              <EmptyState label={t("threatfeed:atlas.empty")} />
            )}

            {!isLoading &&
              !error &&
              tactics.map((tactic) => (
                <>
                  {/* Tactic group header */}
                  <tr key={`hdr-${tactic}`} className="border-t border-slate-800 bg-slate-800/50">
                    <td
                      colSpan={4}
                      className="px-3 py-1.5 font-semibold text-indigo-300 tracking-wide uppercase text-[10px]"
                    >
                      {tactic}
                    </td>
                  </tr>
                  {grouped[tactic].map((entry, i) => (
                    <tr key={`${tactic}-${i}`} className="border-t border-slate-800 hover:bg-slate-800/40">
                      <td className="px-3 py-2 text-slate-500">{/* tactic repeated — blank for grouped layout */}</td>
                      <td className="px-3 py-2 font-mono text-slate-300">
                        {entry.technique_id || "—"}
                      </td>
                      <td className="px-3 py-2 text-slate-400">{entry.technique_name || "—"}</td>
                      <td className="px-3 py-2">
                        <CoveredBadge covered={!!entry.covered} />
                      </td>
                    </tr>
                  ))}
                </>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Tab bar ──────────────────────────────────────────────────────────────────

type Tab = "ioc" | "atlas";

// ─── Page root ────────────────────────────────────────────────────────────────

export default function ThreatFeed() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<Tab>("ioc");

  const tabs: { id: Tab; label: string }[] = [
    { id: "ioc", label: t("threatfeed:tabs.ioc_feed") },
    { id: "atlas", label: t("threatfeed:tabs.atlas_coverage") },
  ];

  return (
    <div className="max-w-5xl">
      <h1 className="text-2xl font-semibold mb-6">{t("threatfeed:title")}</h1>

      {/* Tab bar */}
      <div className="flex gap-1 mb-6 border-b border-slate-800">
        {tabs.map(({ id, label }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`px-4 py-2 text-sm font-medium -mb-px border-b-2 transition-colors ${
              tab === id
                ? "border-indigo-400 text-indigo-300"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "ioc" && <IOCFeedTab />}
      {tab === "atlas" && <AtlasCoverageTab />}
    </div>
  );
}
