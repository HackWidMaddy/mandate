"""Sentinel control plane (Phase 4 skeleton).

ARCHITECTURAL RULE (unchanged): this plane distributes signed bundles and
receives evidence ASYNCHRONOUSLY. It can neither forge policy (clients verify
signatures against local trust anchors) nor disable local enforcement (the
PDP is offline-capable by construction).
"""
