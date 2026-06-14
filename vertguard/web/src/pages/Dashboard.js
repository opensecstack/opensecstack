import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api } from "../lib/api";
export default function Dashboard() {
    const { t } = useTranslation();
    const { data, isLoading, error } = useQuery({
        queryKey: ["health"],
        queryFn: api.health,
        refetchInterval: 30_000,
    });
    if (isLoading)
        return _jsx("div", { className: "text-slate-400", children: t("common:labels.loading") });
    if (error)
        return (_jsx("div", { className: "text-rose-400", children: t("dashboard:errors.health_failed", { detail: String(error) }) }));
    if (!data)
        return null;
    return (_jsxs("div", { children: [_jsx("h1", { className: "text-2xl font-semibold mb-6", children: t("dashboard:title") }), _jsxs("div", { className: "grid grid-cols-2 gap-4 max-w-2xl", children: [_jsx(Card, { label: t("dashboard:fields.status"), value: data.status, accent: data.status === "ok" ? "emerald" : "amber" }), _jsx(Card, { label: t("dashboard:fields.database"), value: data.db }), _jsx(Card, { label: t("dashboard:fields.version"), value: data.version }), _jsx(Card, { label: t("dashboard:fields.commit"), value: data.commit })] }), _jsx("h2", { className: "text-lg font-semibold mt-8 mb-3", children: t("dashboard:modules") }), _jsx("div", { className: "grid grid-cols-3 gap-3 max-w-3xl", children: Object.entries(data.modules).map(([k, v]) => (_jsx(Card, { label: k, value: v }, k))) })] }));
}
function Card({ label, value, accent }) {
    const color = accent === "emerald" ? "text-emerald-300" : accent === "amber" ? "text-amber-300" : "text-slate-100";
    return (_jsxs("div", { className: "bg-slate-900 border border-slate-800 rounded p-3", children: [_jsx("div", { className: "text-xs uppercase text-slate-500", children: label }), _jsx("div", { className: `mt-1 text-sm ${color}`, children: value })] }));
}
