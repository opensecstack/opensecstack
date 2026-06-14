// Fallback client-side reading time calculation used when the server does not provide the field.
export function readingTime(body: string): number {
  const words = body.trim().split(/\s+/).length;
  return Math.max(1, Math.floor(words / 200));
}
