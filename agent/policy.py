"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))


def check(context: PolicyContext) -> tuple[bool, str]:
    """PEP: kiểm tra policy trước khi cho tool chạy."""

    # Rule 1: restricted + egress => DENY (rule tối thiểu bắt buộc)
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "deny: du lieu restricted khong duoc phep egress ra ngoai"

    # Rule 2: kiểm tra expires_at
    if context.expires_at:
        try:
            exp = datetime.fromisoformat(context.expires_at)
            now = datetime.now(timezone.utc)
            if exp <= now:
                return False, "deny: phien da het han (expires_at qua khu)"
        except ValueError:
            return False, "deny: expires_at khong hop le"

    # Rule 3: kiểm tra principal
    if context.principal_id:
        principals = _load_principals()
        principal = principals.get(context.principal_id)
        if principal is None:
            return False, f"deny: principal '{context.principal_id}' khong ton tai"

        # Tính quyền hiệu lực
        allowed_tools = set(principal.get("allowed_tools", []))
        effective = allowed_tools & set(context.agent_scopes) if context.agent_scopes else allowed_tools

        # Nếu delegation_depth > 0, giao thêm với parent_scopes
        if context.delegation_depth > 0 and context.parent_scopes:
            effective = effective & set(context.parent_scopes)

        # Kiểm tra tool có nằm trong quyền hiệu lực không
        if context.requested_tool and context.requested_tool not in effective:
            return False, (
                f"deny: principal '{context.principal_id}' khong co quyen goi "
                f"'{context.requested_tool}' (effective scopes: {sorted(effective)})"
            )

        # Kiểm tra purpose
        valid_purposes = principal.get("purposes", [])
        if context.request_purpose and valid_purposes and context.request_purpose not in valid_purposes:
            return False, (
                f"deny: purpose '{context.request_purpose}' khong hop le "
                f"cho principal '{context.principal_id}'"
            )

    # Mọi check đều pass
    return True, (
        f"allow: {context.requested_tool or 'tool'} duoc phep "
        f"(classification={context.data_classification}, "
        f"principal={context.principal_id or 'none'})"
    )
