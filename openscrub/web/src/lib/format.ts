export function formatTs(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString();
  } catch {
    return iso;
  }
}

export function formatNumber(n: number): string {
  return n.toLocaleString();
}
