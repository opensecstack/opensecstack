type Verdict = "CLEAN" | "SUSPICIOUS" | "BLOCKED";

const styles: Record<Verdict, string> = {
  CLEAN: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
  SUSPICIOUS: "bg-amber-500/20 text-amber-300 border-amber-500/30",
  BLOCKED: "bg-rose-500/20 text-rose-300 border-rose-500/30",
};

export default function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return (
    <span className={`px-2 py-1 rounded text-xs border font-medium ${styles[verdict]}`}>
      {verdict}
    </span>
  );
}
