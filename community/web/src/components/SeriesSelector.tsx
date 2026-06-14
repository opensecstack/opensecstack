import { useQuery } from "@tanstack/react-query";
import { listMySeries } from "@/api/series";

interface SeriesSelectorProps {
  postId?: string;
  value: string | null;
  onChange: (seriesId: string | null) => void;
}

export default function SeriesSelector({ value, onChange }: SeriesSelectorProps) {
  const { data: series } = useQuery({
    queryKey: ["my-series"],
    queryFn: listMySeries,
    staleTime: 30_000,
  });

  if (!series || series.length === 0) return null;

  return (
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-1">Series</label>
      <select
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value || null)}
        className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand/40"
      >
        <option value="">— No series —</option>
        {series.map((s) => (
          <option key={s.id} value={s.id}>
            {s.title}
          </option>
        ))}
      </select>
    </div>
  );
}
