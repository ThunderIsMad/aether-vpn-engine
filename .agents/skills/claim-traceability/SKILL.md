---
name: claim-traceability
description: Verify every quantitative and novelty claim in design docs traces to a cited source that actually says what is claimed. Final pass before publishing.
metadata:
  category: review
---

# Claim Traceability

## Instructions

1. Scan design/*.md for numbers, percentages, "first/unparalleled/novel" claims, RFC/FIPS numbers.
2. Locate cited source in research/*.md; verify it supports the claim AS STATED.
3. Flag upgrades: "2x in scenario X" presented as "30-50% everywhere".
4. Verify crypto parameters against primary standards, not blog summaries.
5. Label each claim ИЗМЕРЕНО (measured) / ГИПОТЕЗА (extrapolated) / ПРОЕКТНО (by design).
6. Novelty claim with no source mapping → flag for rewrite or removal.
