import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api } from "../lib/api";
import VerdictBadge from "../components/VerdictBadge";
export default function Scan() {
    const { t } = useTranslation();
    const [input, setInput] = useState("");
    const [context, setContext] = useState("default");
    const m = useMutation({
        mutationFn: () => api.scan(input, context),
    });
    const result = m.data;
    return (_jsxs("div", { className: "max-w-3xl", children: [_jsx("h1", { className: "text-2xl font-semibold mb-6", children: t("scan:title") }), _jsx("textarea", { value: input, onChange: (e) => setInput(e.target.value), rows: 6, className: "w-full bg-slate-900 border border-slate-700 rounded p-3 text-sm", placeholder: t("scan:placeholder") }), _jsxs("div", { className: "flex items-center gap-3 mt-3", children: [_jsxs("select", { value: context, onChange: (e) => setContext(e.target.value), className: "bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm", children: [_jsx("option", { value: "default", children: "default" }), _jsx("option", { value: "internal_dev_tool", children: "internal_dev_tool" }), _jsx("option", { value: "untrusted_document_content", children: "untrusted_document_content" }), _jsx("option", { value: "user_chat_input", children: "user_chat_input" })] }), _jsx("button", { onClick: () => m.mutate(), disabled: !input.trim() || m.isPending, className: "bg-indigo-500 hover:bg-indigo-400 disabled:opacity-50 rounded px-4 py-1.5 text-sm font-medium", children: m.isPending ? t("scan:scanning") : t("common:actions.scan") })] }), m.error && _jsx("p", { className: "text-rose-400 text-sm mt-3", children: String(m.error) }), result && (_jsxs("div", { className: "mt-6 bg-slate-900 border border-slate-800 rounded p-4", children: [_jsxs("div", { className: "flex items-center gap-3", children: [_jsx(VerdictBadge, { verdict: result.classification }), _jsx("span", { className: "text-sm text-slate-400", children: t("scan:summary", {
                                    confidence: result.confidence.toFixed(3),
                                    duration: result.duration_ms.toFixed(1),
                                    count: result.matches.length,
                                }) })] }), result.matches.length > 0 && (_jsxs("table", { className: "mt-4 w-full text-xs", children: [_jsx("thead", { className: "text-slate-500", children: _jsxs("tr", { children: [_jsx("th", { className: "text-left py-1 pr-3", children: t("scan:table.pattern") }), _jsx("th", { className: "text-left py-1 pr-3", children: t("scan:table.category") }), _jsx("th", { className: "text-left py-1 pr-3", children: t("scan:table.atlas") }), _jsx("th", { className: "text-right py-1", children: t("scan:table.confidence") })] }) }), _jsx("tbody", { children: result.matches.map((mm, i) => (_jsxs("tr", { className: "border-t border-slate-800", children: [_jsx("td", { className: "py-1 pr-3 font-mono text-slate-200", children: mm.pattern_id }), _jsx("td", { className: "py-1 pr-3 text-slate-400", children: mm.category }), _jsx("td", { className: "py-1 pr-3 text-slate-400", children: mm.atlas_technique || "—" }), _jsx("td", { className: "py-1 text-right", children: mm.confidence.toFixed(2) })] }, i))) })] }))] }))] }));
}
