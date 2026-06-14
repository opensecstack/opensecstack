import { useQuery } from "@tanstack/react-query";
import { getCoverage } from "@/api/coverage";
import { CoverageMatrix } from "@/components/CoverageMatrix";
import { Spinner } from "@/components/Spinner";

function LegendItem({
  color,
  label,
}: {
  color: string;
  label: string;
}): JSX.Element {
  return (
    <div className="flex items-center gap-2">
      <div className={`w-4 h-4 rounded ${color}`} />
      <span className="text-xs text-slate-600">{label}</span>
    </div>
  );
}

export default function MitreMap(): JSX.Element {
  const { data, isLoading, error } = useQuery({
    queryKey: ["coverage"],
    queryFn: getCoverage,
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h2 className="text-lg font-semibold text-slate-900">MITRE ATT&CK Coverage Map</h2>
        <div className="flex items-center gap-4">
          <LegendItem color="bg-green-500" label="Detected" />
          <LegendItem color="bg-red-400" label="Not Detected" />
          <LegendItem color="bg-slate-200" label="Not Tested" />
        </div>
      </div>

      <p className="text-sm text-slate-500">
        Each cell represents a MITRE ATT&CK technique. Columns are tactics. Color indicates detection
        status based on scenario runs.
      </p>

      {isLoading && (
        <div className="flex justify-center py-10">
          <Spinner />
        </div>
      )}
      {error && <p className="text-sm text-red-600">Failed to load coverage data.</p>}
      {!isLoading && data && (
        <div className="bg-white border border-slate-200 rounded-md p-4 shadow-sm overflow-auto">
          <CoverageMatrix entries={data.entries} />
        </div>
      )}
    </div>
  );
}
