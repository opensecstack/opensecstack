import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api, ScanResponse } from "../lib/api";
import VerdictBadge from "../components/VerdictBadge";

export default function Scan() {
  const { t } = useTranslation();
  const [input, setInput] = useState("");
  const [context, setContext] = useState("user_chat_input");
  const m = useMutation({
    mutationFn: () => api.scan(input, context),
  });

  const result: ScanResponse | undefined = m.data;

  return (
    <div className="max-w-3xl">
      <h1 className="text-2xl font-semibold mb-6">{t("scan:title")}</h1>
      <textarea
        value={input}
        onChange={(e) => setInput(e.target.value)}
        rows={6}
        className="w-full bg-slate-900 border border-slate-700 rounded p-3 text-sm"
        placeholder={t("scan:placeholder")}
      />
      <div className="flex items-center gap-3 mt-3">
        <select
          value={context}
          onChange={(e) => setContext(e.target.value)}
          className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm"
        >
          <option value="user_chat_input">user_chat_input</option>
          <option value="authenticated_operator">authenticated_operator</option>
          <option value="internal_dev_tool">internal_dev_tool</option>
          <option value="untrusted_third_party">untrusted_third_party</option>
          <option value="untrusted_document_content">untrusted_document_content</option>
        </select>
        <button
          onClick={() => m.mutate()}
          disabled={!input.trim() || m.isPending}
          className="bg-indigo-500 hover:bg-indigo-400 disabled:opacity-50 rounded px-4 py-1.5 text-sm font-medium"
        >
          {m.isPending ? t("scan:scanning") : t("common:actions.scan")}
        </button>
      </div>
      {m.error && <p className="text-rose-400 text-sm mt-3">{String(m.error)}</p>}
      {result && (
        <div className="mt-6 bg-slate-900 border border-slate-800 rounded p-4">
          <div className="flex items-center gap-3">
            <VerdictBadge verdict={result.classification} />
            <span className="text-sm text-slate-400">
              {t("scan:summary", {
                confidence: result.confidence.toFixed(3),
                duration: result.duration_ms.toFixed(1),
                count: result.matches.length,
              })}
            </span>
          </div>
          {result.matches.length > 0 && (
            <table className="mt-4 w-full text-xs">
              <thead className="text-slate-500">
                <tr>
                  <th className="text-left py-1 pr-3">{t("scan:table.pattern")}</th>
                  <th className="text-left py-1 pr-3">{t("scan:table.category")}</th>
                  <th className="text-left py-1 pr-3">{t("scan:table.atlas")}</th>
                  <th className="text-right py-1">{t("scan:table.confidence")}</th>
                </tr>
              </thead>
              <tbody>
                {result.matches.map((mm, i) => (
                  <tr key={i} className="border-t border-slate-800">
                    <td className="py-1 pr-3 font-mono text-slate-200">{mm.pattern_id}</td>
                    <td className="py-1 pr-3 text-slate-400">{mm.category}</td>
                    <td className="py-1 pr-3 text-slate-400">{mm.atlas_technique || "—"}</td>
                    <td className="py-1 text-right">{mm.confidence.toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
