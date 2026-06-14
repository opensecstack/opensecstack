import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { listTracks, type Track } from "@/api/tracks";
import { TrackCard } from "@/components/TrackCard";
import { Button } from "@/components/Button";

function SkeletonCard(): JSX.Element {
  return (
    <div
      className="h-32 animate-pulse rounded-lg border border-slate-200 bg-white p-4"
      aria-hidden="true"
    >
      <div className="mb-3 h-4 w-2/3 rounded bg-slate-200" />
      <div className="mb-2 h-3 w-1/2 rounded bg-slate-100" />
      <div className="flex gap-2">
        <div className="h-4 w-12 rounded bg-slate-100" />
        <div className="h-4 w-16 rounded bg-slate-100" />
      </div>
    </div>
  );
}

export default function TrackList(): JSX.Element {
  const { t } = useTranslation(["tracks", "common"]);
  const [search, setSearch] = useState("");
  const [measure, setMeasure] = useState<string>("");

  const query = useQuery({
    queryKey: ["tracks"],
    queryFn: () => listTracks(),
  });

  const measures = useMemo<string[]>(() => {
    const set = new Set<string>();
    query.data?.tracks.forEach((tr) => (tr.nis2_measures ?? []).forEach((m) => set.add(m)));
    return Array.from(set).sort();
  }, [query.data]);

  const filtered = useMemo<Track[]>(() => {
    if (!query.data) return [];
    const s = search.trim().toLowerCase();
    return query.data.tracks.filter((tr) => {
      if (measure && !(tr.nis2_measures ?? []).includes(measure)) return false;
      if (!s) return true;
      return (
        tr.title.toLowerCase().includes(s) ||
        tr.slug.toLowerCase().includes(s) ||
        tr.audience.toLowerCase().includes(s)
      );
    });
  }, [query.data, search, measure]);

  return (
    <section className="space-y-4">
      <h1 className="text-2xl font-bold">{t("tracks:list.title")}</h1>

      <div className="flex flex-wrap items-end gap-3">
        <label className="block text-sm">
          <span className="mb-1 block text-slate-700">{t("common:labels.search")}</span>
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t("tracks:list.searchPlaceholder")}
            className="w-64 rounded-md border border-slate-300 px-3 py-2 text-sm"
          />
        </label>
        <label className="block text-sm">
          <span className="mb-1 block text-slate-700">{t("tracks:list.filterMeasure")}</span>
          <select
            value={measure}
            onChange={(e) => setMeasure(e.target.value)}
            className="rounded-md border border-slate-300 bg-white px-2 py-2 text-sm"
          >
            <option value="">{t("tracks:list.allMeasures")}</option>
            {measures.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </label>
      </div>

      {query.isLoading && (
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <SkeletonCard key={i} />
          ))}
        </div>
      )}

      {query.isError && (
        <div className="space-y-2 rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-800">
          <p>{t("common:errors.generic")}</p>
          <Button variant="secondary" onClick={() => void query.refetch()}>
            {t("common:buttons.retry")}
          </Button>
        </div>
      )}

      {query.data && filtered.length === 0 && !query.isLoading && (
        <p className="text-slate-600">{t("common:labels.empty")}</p>
      )}

      <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
        {filtered.map((track) => (
          <TrackCard key={track.id} track={track} />
        ))}
      </div>
    </section>
  );
}
