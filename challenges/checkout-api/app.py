"""Checkout API — ForgeLab demo challenge fixture.

Contains three deliberate defects for agents to find and fix:
  1. Race condition on inventory decrement (non-atomic read-modify-write).
  2. Discount is subtracted as a flat amount instead of a percentage.
  3. Missing validation: non-positive quantities are accepted.
"""

import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Checkout API")

PRICES = {"widget": 20.00, "gizmo": 45.50}
DISCOUNTS = {"SAVE10": 0.10, "SAVE25": 0.25}
INVENTORY = {"widget": 10, "gizmo": 5}


class CheckoutRequest(BaseModel):
    sku: str
    quantity: int
    discount_code: str | None = None


def reset_inventory(widget: int = 10, gizmo: int = 5) -> None:
    INVENTORY["widget"] = widget
    INVENTORY["gizmo"] = gizmo


@app.post("/checkout")
def checkout(req: CheckoutRequest):
    if req.sku not in PRICES:
        raise HTTPException(status_code=404, detail="unknown sku")

    # BUG 3: no guard against quantity <= 0

    current = INVENTORY[req.sku]
    # BUG 1: read-modify-write without a lock, and no stock check
    time.sleep(0.002)
    INVENTORY[req.sku] = current - req.quantity

    subtotal = PRICES[req.sku] * req.quantity

    total = subtotal
    if req.discount_code:
        rate = DISCOUNTS.get(req.discount_code)
        if rate is None:
            raise HTTPException(status_code=400, detail="invalid discount code")
        # BUG 2: rate treated as a flat currency amount, not a percentage
        total = subtotal - rate

    return {
        "sku": req.sku,
        "quantity": req.quantity,
        "subtotal": round(subtotal, 2),
        "total": round(total, 2),
        "remaining_stock": INVENTORY[req.sku],
    }


@app.get("/inventory")
def inventory():
    return INVENTORY
