"""Regression suite for the checkout API.

Three of these fail against the seeded defects — that gap is the challenge.
"""

from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app import app, reset_inventory

client = TestClient(app)


@pytest.fixture(autouse=True)
def _fresh_inventory():
    reset_inventory()
    yield


def test_basic_total_without_discount():
    r = client.post("/checkout", json={"sku": "widget", "quantity": 2})
    assert r.status_code == 200
    assert r.json()["total"] == 40.00


def test_unknown_sku_is_rejected():
    r = client.post("/checkout", json={"sku": "nope", "quantity": 1})
    assert r.status_code == 404


def test_invalid_discount_code_is_rejected():
    r = client.post(
        "/checkout", json={"sku": "widget", "quantity": 1, "discount_code": "BOGUS"}
    )
    assert r.status_code == 400


def test_discount_is_a_percentage_of_the_order():
    """SAVE10 on 2 widgets ($40) should cost $36.00, not $39.90."""
    r = client.post(
        "/checkout", json={"sku": "widget", "quantity": 2, "discount_code": "SAVE10"}
    )
    assert r.status_code == 200
    assert r.json()["total"] == 36.00


def test_non_positive_quantity_is_rejected():
    r = client.post("/checkout", json={"sku": "widget", "quantity": -5})
    assert r.status_code in (400, 422)


def test_inventory_never_oversells_under_concurrency():
    """20 concurrent single-unit orders against 10 units of stock."""
    reset_inventory(widget=10)

    def buy(_):
        return client.post("/checkout", json={"sku": "widget", "quantity": 1}).status_code

    with ThreadPoolExecutor(max_workers=20) as pool:
        codes = list(pool.map(buy, range(20)))

    assert client.get("/inventory").json()["widget"] >= 0
    assert codes.count(200) == 10
