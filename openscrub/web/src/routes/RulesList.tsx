import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { Trash2 } from "lucide-react";
import { Button } from "@/components/Button";
import { Spinner } from "@/components/Spinner";
import { listRules, deleteRule, type Rule, type RuleType } from "@/api/rules";
import { formatTs } from "@/lib/format";

const PAGE_SIZE = 25;

type TypeFilter = RuleType | "";

function isRuleType(s: string): s is RuleType {
  return s === "blocklist" || s === "ratelimit" || s === "syncookie";
}

export default function RulesList(): JSX.Element {
  const { t } = useTranslation(["common", "rules"]);
  const qc = useQueryClient();
  // URL-synced state so reload / share-link preserves the page +
  // filter the operator was looking at. The previous useState pair
  // dropped both on every navigation, which made deep links like
  // "page 5 of /rules?type=ratelimit" effectively useless.
  const [searchParams, setSearchParams] = useSearchParams();
  const offset = Math.max(0, parseInt(searchParams.get("offset") ?? "0", 10) || 0);
  const typeFilter: TypeFilter = (() => {
    const v = searchParams.get("type") ?? "";
    return isRuleType(v) ? v : "";
  })();

  function patchParams(next: Partial<{ offset: number; type: TypeFilter }>): void {
    const sp = new URLSearchParams(searchParams);
    if (next.type !== undefined) {
      if (next.type === "") sp.delete("type");
      else sp.set("type", next.type);
    }
    if (next.offset !== undefined) {
      if (next.offset === 0) sp.delete("offset");
      else sp.set("offset", String(next.offset));
    }
    setSearchParams(sp, { replace: true });
  }

  const { data, isLoading, isError } = useQuery({
    queryKey: ["rules", typeFilter, offset],
    queryFn: () =>
      listRules({
        limit: PAGE_SIZE,
        offset,
        ...(typeFilter ? { type: typeFilter } : {}),
      }),
  });

  const del = useMutation({
    mutationFn: (id: string) => deleteRule(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });

  if (isLoading) return <Spinner />;
  if (isError) return <p className="text-red-600">{t("common:labels.error")}</p>;

  const rules = data?.rules ?? [];
  // `count` is the page size (rows on this page) per the OpenAPI
  // contract — NOT the grand total. The UI used to render this as
  // the X/total denominator, which both lied to the operator and
  // broke the "next" disable check (it was always `false` once the
  // page was full). Until the API exposes a real total we infer
  // hasMore from "page is full" and render the denominator as
  // unknown ("?").
  const pageRows = data?.count ?? rules.length;
  const hasMore = pageRows >= PAGE_SIZE;
  // Port is meaningful only for syncookie rules. Hide the column
  // entirely when the active filter is blocklist/ratelimit so the
  // table doesn't show an empty "—" column for every row. With
  // typeFilter=="" (all types) we keep the heuristic — show the
  // column iff any visible rule actually has a port.
  const showPort =
    typeFilter === "syncookie" ||
    (typeFilter === "" && rules.some((r) => r.port != null));

  function onTypeChange(value: string): void {
    const next: TypeFilter = isRuleType(value) ? value : "";
    patchParams({ type: next, offset: 0 });
  }

  return (
    <div className="space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">{t("rules:title")}</h1>
        <span className="text-sm text-slate-500">
          {t("rules:total", { count: pageRows })}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <label htmlFor="rules-type-filter" className="text-sm text-slate-600">
          {t("rules:fields.type")}
        </label>
        <select
          id="rules-type-filter"
          value={typeFilter}
          onChange={(e) => onTypeChange(e.target.value)}
          className="border border-slate-300 rounded-md px-2 py-1 text-sm"
        >
          <option value="">{t("rules:filter.all")}</option>
          <option value="blocklist">{t("rules:types.blocklist")}</option>
          <option value="ratelimit">{t("rules:types.ratelimit")}</option>
          <option value="syncookie">{t("rules:types.syncookie")}</option>
        </select>
      </div>
      {rules.length === 0 ? (
        <p className="text-slate-500">{t("common:labels.empty")}</p>
      ) : (
        <table className="w-full bg-white rounded-md overflow-hidden text-sm shadow-sm">
          <thead className="bg-slate-100 text-left">
            <tr>
              <th className="px-3 py-2">{t("rules:fields.type")}</th>
              <th className="px-3 py-2">{t("rules:fields.cidr")}</th>
              {showPort && <th className="px-3 py-2">{t("rules:fields.port")}</th>}
              <th className="px-3 py-2">{t("rules:fields.pps")}</th>
              <th className="px-3 py-2">{t("rules:fields.ttl")}</th>
              <th className="px-3 py-2">{t("rules:fields.source")}</th>
              <th className="px-3 py-2">{t("rules:fields.created_at")}</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r: Rule) => (
              <tr key={r.id} className="border-t border-slate-100">
                <td className="px-3 py-2">{t(`rules:types.${r.type}`)}</td>
                <td className="px-3 py-2 font-mono">{r.cidr ?? "—"}</td>
                {showPort && <td className="px-3 py-2">{r.port ?? "—"}</td>}
                <td className="px-3 py-2">{r.pps ?? "—"}</td>
                <td className="px-3 py-2">{r.ttl_seconds}</td>
                <td className="px-3 py-2">{r.source}</td>
                <td className="px-3 py-2">{formatTs(r.created_at)}</td>
                <td className="px-3 py-2 text-right">
                  <button
                    aria-label={t("common:actions.delete")}
                    onClick={() => del.mutate(r.id)}
                    className="text-red-600 hover:text-red-800"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="flex items-center gap-2">
        <Button
          variant="secondary"
          disabled={offset <= 0}
          onClick={() => patchParams({ offset: Math.max(0, offset - PAGE_SIZE) })}
        >
          ←
        </Button>
        <span className="text-sm text-slate-600">
          {offset + 1}–{offset + rules.length} / ?
        </span>
        <Button
          variant="secondary"
          disabled={!hasMore}
          onClick={() => patchParams({ offset: offset + PAGE_SIZE })}
        >
          →
        </Button>
      </div>
    </div>
  );
}
