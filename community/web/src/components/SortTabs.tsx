interface SortTabsProps {
  value: string;
  onChange: (sort: string) => void;
}

const SORTS = [
  { key: "latest", label: "Latest" },
  { key: "top_week", label: "Top: week" },
  { key: "top_month", label: "Top: month" },
  { key: "top_all", label: "Top: all time" },
  { key: "rising", label: "Rising" },
];

export default function SortTabs({ value, onChange }: SortTabsProps) {
  return (
    <div className="flex gap-1 mb-4 flex-wrap">
      {SORTS.map((s) => (
        <button
          key={s.key}
          onClick={() => onChange(s.key)}
          className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
            value === s.key
              ? "bg-brand text-white"
              : "bg-white border border-gray-200 text-gray-600 hover:border-brand/40 hover:text-brand"
          }`}
        >
          {s.label}
        </button>
      ))}
    </div>
  );
}
