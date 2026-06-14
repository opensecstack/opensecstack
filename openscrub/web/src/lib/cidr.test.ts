import { describe, expect, it } from "vitest";
import { isValidCidr } from "./cidr";

describe("isValidCidr", () => {
  it.each([
    "10.0.0.0/8",
    "192.0.2.0/24",
    "203.0.113.7/32",
    "2001:db8::/32",
    "::1/128",
    "fe80::1/64",
  ])("accepts %s", (input) => {
    expect(isValidCidr(input)).toBe(true);
  });

  it.each([
    "",
    "10.0.0.0",
    "10.0.0.0/33",
    "256.0.0.0/8",
    "10.0.0.0/-1",
    "::::/64",
    "2001::1::2/64",
    "2001:db8::/129",
    "ZZZZ::/64",
  ])("rejects %s", (input) => {
    expect(isValidCidr(input)).toBe(false);
  });
});
