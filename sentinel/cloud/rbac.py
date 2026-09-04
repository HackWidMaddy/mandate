"""Role-based access control for the control plane.

Roles per the enterprise blueprint; the matrix below is the single source of
truth and is exercised by tests. Deny-by-default: an endpoint not listed for
a role is forbidden.
"""
from __future__ import annotations

from typing import Dict, FrozenSet

ORG_OWNER = "OrgOwner"
SECURITY_ADMIN = "SecurityAdmin"
POLICY_AUTHOR = "PolicyAuthor"
POLICY_APPROVER = "PolicyApprover"
DEVELOPER = "Developer"
AUDITOR = "Auditor"
SERVICE_ACCOUNT = "ServiceAccount"

ALL_ROLES = (ORG_OWNER, SECURITY_ADMIN, POLICY_AUTHOR, POLICY_APPROVER,
             DEVELOPER, AUDITOR, SERVICE_ACCOUNT)

# capability -> roles allowed
MATRIX: Dict[str, FrozenSet[str]] = {
    "bundles.upload": frozenset({SECURITY_ADMIN, SERVICE_ACCOUNT}),
    "bundles.read": frozenset(ALL_ROLES),
    "receipts.upload": frozenset({SERVICE_ACCOUNT, SECURITY_ADMIN}),
    "receipts.read": frozenset({ORG_OWNER, SECURITY_ADMIN, AUDITOR}),
    "webhooks.write": frozenset({ORG_OWNER, SECURITY_ADMIN}),
    "webhooks.read": frozenset({ORG_OWNER, SECURITY_ADMIN, AUDITOR}),
    "admin.overview": frozenset({ORG_OWNER, SECURITY_ADMIN, AUDITOR}),
}


def allowed(capability: str, role: str) -> bool:
    return role in MATRIX.get(capability, frozenset())


class Forbidden(Exception):
    pass


def require(capability: str, claims: dict) -> None:
    if not allowed(capability, claims.get("role", "")):
        raise Forbidden(
            f"role {claims.get('role')!r} lacks capability '{capability}'")
