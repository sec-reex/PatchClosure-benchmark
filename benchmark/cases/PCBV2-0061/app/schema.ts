import { list } from '@keystone-6/core';
import { allowAll, denyAll } from '@keystone-6/core/access';
import { text } from '@keystone-6/core/fields';

// PatchClosure-Bench: keystone6-cve-2026-33326
//
// A minimal, REAL Keystone-6 schema that reproduces the isFilterable
// access-control surface behind CVE-2025-46720 (original) and its
// incomplete-fix follow-up CVE-2026-33326 (residual, findMany `cursor`).
//
// The `code` field:
//   * isIndexed: 'unique'      -> appears in <List>WhereUniqueInput (findOne/cursor/update/delete `where`)
//   * isFilterable: () => false -> a FUNCTION (per advisory: the affected configuration).
//                                  Field stays in the `where` filter schema but is runtime-blocked
//                                  by checkFilterOrderAccess. Static `isFilterable:false` is NOT
//                                  affected (advisory workaround) precisely because it is not a fn.
//   * access.read: denyAll     -> the value can never be SELECTed directly; the only way to learn
//                                  it is to abuse a filter/cursor as a value-oracle.
export const lists = {
  Secret: list({
    // operation-level: public list (no auth). The confidentiality boundary is the
    // FIELD-level access + isFilterable on `code`, exactly the boundary the CVEs break.
    access: allowAll,
    fields: {
      label: text({ validation: { isRequired: true } }),
      code: text({
        isIndexed: 'unique',
        access: { read: denyAll },
        isFilterable: () => false,
      }),
    },
  }),
};
