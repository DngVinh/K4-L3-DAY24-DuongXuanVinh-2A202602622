"""Checkpoint OBO: deny vượt quyền và vẫn phục vụ được principal hợp lệ."""
from __future__ import annotations

import json
from pathlib import Path

from agent import tools
from agent.loop import run_once
from agent.policy import PolicyContext, check


def _ctx(**changes):
    values = dict(
        data_classification="restricted",
        request_purpose="support-reply",
        agent_owner="lab24-agent/run-b",
        delegation_depth=0,
        egress_enabled=False,
        principal_id="dpo",
        requested_tool="read_customer",
        agent_scopes=("search_docs", "read_customer"),
        parent_scopes=(),
        expires_at="2099-01-01T00:00:00+00:00",
    )
    values.update(changes)
    return PolicyContext(**values)


def test_support_l1_cannot_read_restricted_customer():
    allowed, reason = check(_ctx(principal_id="support_l1"))
    assert allowed is False and reason


def test_dpo_can_read_for_valid_purpose():
    allowed, reason = check(_ctx())
    assert allowed is True and reason


def test_delegation_cannot_expand_parent_scope():
    allowed, reason = check(_ctx(delegation_depth=1, parent_scopes=("search_docs",)))
    assert allowed is False and reason


def test_empty_agent_or_parent_scopes_grant_no_tools():
    for context in (_ctx(agent_scopes=()),
                    _ctx(delegation_depth=1, parent_scopes=())):
        allowed, reason = check(context)
        assert allowed is False and reason


def test_expired_or_unknown_identity_is_denied():
    for context in (_ctx(expires_at="2000-01-01T00:00:00+00:00"),
                    _ctx(principal_id="nobody")):
        allowed, reason = check(context)
        assert allowed is False and reason


def test_runner_checks_principal_at_tool_boundary(clean_sink, tmp_path, monkeypatch):
    seen = []
    real_read = tools.read_customer

    def spy(customer_id, *args, **kwargs):
        seen.append(customer_id)
        return real_read(customer_id, *args, **kwargs)

    monkeypatch.setattr(tools, "read_customer", spy)
    query = "Tổng hợp các ticket còn mở tuần này"
    support_dir = tmp_path / "support"
    dpo_dir = tmp_path / "dpo"
    run_once(query, mock=True, log_dir=support_dir, principal_id="support_l1")
    assert not seen, "support_l1 đã đọc record chứa CCCD/STK"
    run_once(query, mock=True, log_dir=dpo_dir, principal_id="dpo")
    assert seen, "dpo hợp lệ bị chặn mọi read_customer"
    for path, principal in ((support_dir / "ledger.jsonl", "support_l1"),
                            (dpo_dir / "ledger.jsonl", "dpo")):
        entries = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        assert entries and all(e.get("on_behalf_of") == principal for e in entries)
        assert all(e.get("run_id") and e.get("expires_at") for e in entries)
    support = [json.loads(line) for line in (support_dir / "ledger.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any(e.get("tool") == "read_customer" and e.get("decision") == "deny" for e in support)
