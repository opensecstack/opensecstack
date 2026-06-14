import clsx from "clsx";

const styles: Record<string, string> = {
  clear: "bg-slate-200 text-slate-800",
  green: "bg-emerald-100 text-emerald-800",
  amber: "bg-amber-100 text-amber-800",
  red: "bg-red-200 text-red-900",
};

export function TlpBadge({ tlp }: { tlp: string }): JSX.Element {
  const key = tlp.toLowerCase();
  return (
    <span className={clsx("inline-block rounded px-2 py-0.5 text-xs font-mono uppercase", styles[key] ?? "bg-slate-200 text-slate-800")}>
      tlp:{tlp}
    </span>
  );
}
