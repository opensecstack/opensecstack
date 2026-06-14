import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/Button";
import { Spinner } from "@/components/Spinner";
import { TlpBadge } from "@/components/TlpBadge";
import {
  listConstituencies,
  createConstituency,
  type ConstituencyKind,
  type Tlp,
  type CreateConstituencyInput,
} from "@/api/constituencies";
import { formatTs } from "@/lib/format";

export default function Constituencies(): JSX.Element {
  const { t } = useTranslation(["common", "constituencies"]);
  const qc = useQueryClient();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["constituencies"],
    queryFn: () => listConstituencies(100, 0),
  });

  const [draft, setDraft] = useState<CreateConstituencyInput>({
    name: "",
    kind: "essential",
    sector: "",
    tlp_default: "green",
    primary_contact: "",
    secondary_contact_email: "",
  });
  const create = useMutation({
    mutationFn: (input: CreateConstituencyInput) => createConstituency(input),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["constituencies"] });
      setDraft({ name: "", kind: "essential", sector: "", tlp_default: "green", primary_contact: "", secondary_contact_email: "" });
    },
  });

  function onSubmit(e: FormEvent): void {
    e.preventDefault();
    create.mutate(draft);
  }

  if (isLoading) return <Spinner />;
  if (isError) return <p className="text-red-600">{t("common:labels.error")}</p>;

  const items = data?.constituencies ?? [];

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">{t("constituencies:title")}</h1>

      <form onSubmit={onSubmit} className="bg-white rounded-md shadow-sm p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
        <h2 className="md:col-span-2 text-sm font-semibold">{t("constituencies:add_title")}</h2>
        <input
          placeholder={t("constituencies:fields.name")}
          value={draft.name}
          onChange={(e) => setDraft({ ...draft, name: e.target.value })}
          className="border border-slate-300 rounded-md px-2 py-1.5 text-sm"
          required
        />
        <select
          value={draft.kind}
          onChange={(e) => setDraft({ ...draft, kind: e.target.value as ConstituencyKind })}
          className="border border-slate-300 rounded-md px-2 py-1.5 text-sm"
        >
          <option value="essential">{t("constituencies:kinds.essential")}</option>
          <option value="important">{t("constituencies:kinds.important")}</option>
          <option value="out_of_scope">{t("constituencies:kinds.out_of_scope")}</option>
        </select>
        <input
          placeholder={t("constituencies:fields.sector")}
          value={draft.sector}
          onChange={(e) => setDraft({ ...draft, sector: e.target.value })}
          className="border border-slate-300 rounded-md px-2 py-1.5 text-sm"
        />
        <select
          value={draft.tlp_default}
          onChange={(e) => setDraft({ ...draft, tlp_default: e.target.value as Tlp })}
          className="border border-slate-300 rounded-md px-2 py-1.5 text-sm"
        >
          <option value="clear">TLP:CLEAR</option>
          <option value="green">TLP:GREEN</option>
          <option value="amber">TLP:AMBER</option>
          <option value="red">TLP:RED</option>
        </select>
        <input
          placeholder={t("constituencies:fields.primary_contact")}
          value={draft.primary_contact}
          onChange={(e) => setDraft({ ...draft, primary_contact: e.target.value })}
          className="border border-slate-300 rounded-md px-2 py-1.5 text-sm"
        />
        <input
          placeholder={t("constituencies:fields.secondary_contact")}
          value={draft.secondary_contact_email ?? ""}
          onChange={(e) => setDraft({ ...draft, secondary_contact_email: e.target.value || undefined })}
          className="border border-slate-300 rounded-md px-2 py-1.5 text-sm"
        />
        <div className="md:col-span-2">
          <Button type="submit" disabled={create.isPending}>{t("common:actions.create")}</Button>
        </div>
      </form>

      {items.length === 0 ? (
        <p className="text-slate-500">{t("common:labels.empty")}</p>
      ) : (
        <table className="w-full bg-white rounded-md text-sm shadow-sm overflow-hidden">
          <thead className="bg-slate-100 text-left">
            <tr>
              <th className="px-3 py-2">{t("constituencies:fields.name")}</th>
              <th className="px-3 py-2">{t("constituencies:fields.kind")}</th>
              <th className="px-3 py-2">{t("constituencies:fields.sector")}</th>
              <th className="px-3 py-2">{t("constituencies:fields.tlp_default")}</th>
              <th className="px-3 py-2">{t("constituencies:fields.primary_contact")}</th>
              <th className="px-3 py-2">{t("constituencies:fields.secondary_contact")}</th>
              <th className="px-3 py-2">{t("constituencies:fields.created_at")}</th>
            </tr>
          </thead>
          <tbody>
            {items.map((c) => (
              <tr key={c.id} className="border-t border-slate-100">
                <td className="px-3 py-2 font-medium">{c.name}</td>
                <td className="px-3 py-2">{t(`constituencies:kinds.${c.kind}`)}</td>
                <td className="px-3 py-2">{c.sector}</td>
                <td className="px-3 py-2"><TlpBadge tlp={c.tlp_default} /></td>
                <td className="px-3 py-2">{c.primary_contact ?? "—"}</td>
                <td className="px-3 py-2">{c.secondary_contact_email ?? "—"}</td>
                <td className="px-3 py-2">{formatTs(c.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
