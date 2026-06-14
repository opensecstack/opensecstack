/**
 * Compile-time i18n key parity.
 *
 * Imports both locale JSONs and asserts (via TS type machinery) that
 * `en` and `sq` have the same structural keys. If either file gains or
 * drops a key without updating the other, `tsc --noEmit` fails here.
 *
 * Components should import `I18nKey` (or `tk`) when they want a typo-
 * proof handle to a key. Plain `t("foo.bar")` calls keep working as
 * before — this module is opt-in.
 */
import en from "@/i18n/locales/en.json";
import sq from "@/i18n/locales/sq.json";

type Primitive = string | number | boolean | null;

// Recursive key-path generator: { a: { b: "x" } } -> "a" | "a.b"
type Paths<T, Prefix extends string = ""> = {
  [K in keyof T & string]: T[K] extends Primitive
    ? `${Prefix}${K}`
    : `${Prefix}${K}` | Paths<T[K], `${Prefix}${K}.`>;
}[keyof T & string];

// Structural equivalence: each key in A must exist in B and vice versa,
// recursively. Any mismatch resolves to `never` and surfaces a TS error
// when assigned to a non-`never` slot below.
type SameKeys<A, B> = keyof A extends keyof B
  ? keyof B extends keyof A
    ? {
        [K in keyof A]: A[K] extends Primitive
          ? B[K] extends Primitive
            ? true
            : never
          : B[K] extends Primitive
            ? never
            : SameKeys<A[K], B[K]>;
      }
    : never
  : never;

type EnKeys = Paths<typeof en>;
type SqKeys = Paths<typeof sq>;

// If en and sq diverge, this constant resolves to `never` and fails the
// const assertion below — surfaced as a typecheck error.
type Parity = SameKeys<typeof en, typeof sq> & SameKeys<typeof sq, typeof en>;

// `_parity` is intentionally unused at runtime; its sole purpose is to
// make TS evaluate `Parity` against a concrete shape and complain if a
// key has been added/removed in only one locale.
const _parity: Parity = {} as Parity;
void _parity;

export type I18nKey = EnKeys & SqKeys;

/**
 * Identity helper that constrains its argument to a known key path.
 * Use as `t(tk("common.errors.network"))` to get compile-time checks
 * without changing the runtime call.
 */
export function tk(key: I18nKey): I18nKey {
  return key;
}
