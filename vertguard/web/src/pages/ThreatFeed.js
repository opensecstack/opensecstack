import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api } from "../lib/api";
export default function ThreatFeed() {
    const { t } = useTranslation();
    const { data, isLoading, error } = useQuery({
        queryKey: ["atlas-coverage"],
        queryFn: api.atlasCoverage,
    });
    return (_jsxs("div", { children: [_jsx("h1", { className: "text-2xl font-semibold mb-6", children: t("threatfeed:title") }), isLoading && _jsx("div", { className: "text-slate-400", children: t("common:labels.loading") }), error && (_jsx("div", { className: "text-rose-400", children: t("threatfeed:errors.load_failed", { detail: String(error) }) })), data ? (_jsx("pre", { className: "bg-slate-900 border border-slate-800 rounded p-4 text-xs overflow-auto max-h-[70vh]", children: JSON.stringify(data, null, 2) })) : null] }));
}
