"""Durable audit evidence.

The `audit_events` table itself lives with the identity models, because it was
created by that migration and shares their tenant-scoping conventions. The
writing policy — redaction, outcome normalization, validation — lives here,
where every future caller can find it.
"""
