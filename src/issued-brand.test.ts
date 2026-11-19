/**
 * omitly#1864, docs/pass-contract.md §8.1 T18 (a): an `Issued` cannot be built outside outcome.ts. Its brand is a module-private unique
 * symbol, so a literal that names `outcome`, `why` and `lead` is a type error, and the `@ts-expect-error` below makes `tsc` (the first step
 * of `npm test`) fail the build if that ever stops being true. (A cast can still lie; T18 (b) in pass-contract-v02.test.ts scans every
 * source file other than outcome.ts for an `outcome` literal, and the bundle and overlay too.)
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { capped, isFailure, type Issued } from "./outcome.js";

// @ts-expect-error -- the ISSUED brand is not exported: this literal is not an Issued.
const forged: Issued = { outcome: "safe_to_send", why: [], lead: "" };

test("T18 (a): an Issued is only ever made by outcome.ts, and what it makes is frozen", () => {
  assert.equal(forged.outcome, "safe_to_send", "the forgery compiled only because of the expected error above; it is not something a surface can use");
  const real = capped(null, [{ at: "needs_review", why: "x" }]);
  assert.equal(isFailure(real), false);
  assert.ok(Object.isFrozen(real));
  assert.notEqual(Object.getOwnPropertySymbols(real).length, 0, "the real value carries the private brand");
  assert.equal(Object.getOwnPropertySymbols(forged).length, 0, "a forged literal does not");
});
