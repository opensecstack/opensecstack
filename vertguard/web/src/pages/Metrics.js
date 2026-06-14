import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useTranslation } from "react-i18next";
export default function Metrics() {
    const { t } = useTranslation();
    return (_jsxs("div", { children: [_jsx("h1", { className: "text-2xl font-semibold mb-6", children: t("metrics:title") }), _jsxs("div", { className: "bg-slate-900 border border-slate-800 rounded p-4 max-w-xl", children: [_jsx("p", { className: "text-sm text-slate-300 mb-3", children: t("metrics:intro") }), _jsx("a", { href: "/metrics", target: "_blank", rel: "noreferrer", className: "inline-block bg-indigo-500 hover:bg-indigo-400 rounded px-3 py-1.5 text-sm font-medium", children: t("metrics:open") }), _jsx("p", { className: "text-xs text-slate-500 mt-3", children: t("metrics:footnote") })] })] }));
}
