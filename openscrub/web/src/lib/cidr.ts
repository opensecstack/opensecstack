// Strict-ish CIDR validator. The v6 path defers to a structural check
// rather than a permissive regex (the prior /^[0-9a-fA-F:]+/ pattern
// happily accepted "::::/64" and similar trash).

const CIDR_V4 = /^(\d{1,3}\.){3}\d{1,3}\/(\d|[12]\d|3[0-2])$/;

export function isValidCidr(input: string): boolean {
  if (CIDR_V4.test(input)) {
    const [addr] = input.split("/");
    return addr.split(".").every((o) => {
      const n = Number(o);
      return n >= 0 && n <= 255;
    });
  }
  return isValidV6Cidr(input);
}

function isValidV6Cidr(input: string): boolean {
  const slash = input.lastIndexOf("/");
  if (slash <= 0) return false;
  const addr = input.slice(0, slash);
  const prefix = Number(input.slice(slash + 1));
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return false;
  return isValidV6Address(addr);
}

function isValidV6Address(addr: string): boolean {
  // At most one "::" allowed.
  const dblColon = addr.split("::");
  if (dblColon.length > 2) return false;

  const expand = (segment: string): string[] =>
    segment === "" ? [] : segment.split(":");

  const head = expand(dblColon[0]);
  const tail = dblColon.length === 2 ? expand(dblColon[1]) : [];

  const total = head.length + tail.length;
  if (dblColon.length === 1) {
    if (total !== 8) return false;
  } else {
    if (total > 7) return false; // "::" must compress at least one group
  }

  const groups = [...head, ...tail];
  return groups.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g));
}
