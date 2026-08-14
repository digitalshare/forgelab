# Challenge: Broken Checkout API

Baseline: **3 of 6 tests fail.** Each failure maps to one seeded defect.

| Defect | Failing test |
|---|---|
| Race condition on inventory decrement (non-atomic read-modify-write, no stock check) | `test_inventory_never_oversells_under_concurrency` |
| Discount rate subtracted as a flat amount instead of a percentage | `test_discount_is_a_percentage_of_the_order` |
| Missing validation — non-positive quantities accepted | `test_non_positive_quantity_is_rejected` |

Success condition: 6/6 passing, with a minimal diff. Reference fix is
+18/-15 on `app.py` alone — use that as the diff-quality yardstick.

Setup: `pip install fastapi uvicorn pytest httpx && python3 -m pytest -q`
