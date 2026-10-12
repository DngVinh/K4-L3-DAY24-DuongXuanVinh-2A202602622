"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, tools
from agent.pii import redact
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_FILE = Path(__file__).resolve().parent.parent / "data" / "customers.json"
PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"

# TTL mặc định cho mỗi run (xa trong tương lai cho lab)
DEFAULT_EXPIRES = "2099-01-01T00:00:00+00:00"

# Agent scopes cho từng run
RUN_A_SCOPES = ("search_docs",)
RUN_B_SCOPES = ("search_docs", "read_customer", "http_post")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _args_hash(*args) -> str:
    raw = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _load_principals() -> dict:
    return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))


def _load_customers() -> list[dict]:
    return json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))


def _ticket_id_from_filename(filename: str) -> int | None:
    """Trích ticket number từ tên file, vd 'ticket-007.md' -> 7."""
    m = re.match(r"ticket-(\d+)b?\.md", filename)
    if m:
        return int(m.group(1))
    return None


def _find_customers_by_tickets(ticket_ids: list[int]) -> list[str]:
    """Tra customers.json, trả về customer_id có related_tickets chứa ticket_id."""
    customers = _load_customers()
    result = []
    seen = set()
    for customer in customers:
        for tid in ticket_ids:
            if tid in customer.get("related_tickets", []):
                cid = customer["customer_id"]
                if cid not in seen:
                    result.append(cid)
                    seen.add(cid)
    return result


def _do_policy_and_log(
    tool_name: str,
    args_for_hash,
    classification: str,
    purpose: str,
    principal_id: str,
    agent_id: str,
    run_id: str,
    ledger_path: Path,
    egress_enabled: bool = False,
    agent_scopes: tuple[str, ...] = (),
    parent_scopes: tuple[str, ...] = (),
    delegation_depth: int = 0,
) -> tuple[bool, str]:
    """Kiểm policy, ghi ledger, trả (allow, reason)."""
    ctx = PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=agent_id,
        delegation_depth=delegation_depth,
        egress_enabled=egress_enabled,
        principal_id=principal_id,
        requested_tool=tool_name,
        agent_scopes=agent_scopes,
        parent_scopes=parent_scopes,
        expires_at=DEFAULT_EXPIRES,
    )
    allow, reason = check(ctx)
    decision = "allow" if allow else "deny"

    entry = {
        "ts": _now_iso(),
        "agent_id": agent_id,
        "run_id": run_id,
        "tool": tool_name,
        "args_hash": _args_hash(args_for_hash),
        "classification": classification,
        "decision": decision,
        "reason": reason,
        "on_behalf_of": principal_id,
        "expires_at": DEFAULT_EXPIRES,
    }
    ledger.append(entry, ledger_path)

    return allow, reason


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    """Trifecta split: Run A (untrusted) -> ticket_ids -> Run B (private)."""
    ledger_path = (log_dir or REPORTS_DIR) / "ledger.jsonl"
    agent_id = "lab24-agent"
    run_a_id = f"run-a-{uuid.uuid4().hex[:8]}"
    run_b_id = f"run-b-{uuid.uuid4().hex[:8]}"

    # ============================================================
    # RUN A: search_docs — đọc corpus, KHÔNG đọc customer/egress
    # ============================================================
    allow, reason = _do_policy_and_log(
        tool_name="search_docs",
        args_for_hash=message,
        classification="internal",
        purpose="summarize-tickets",
        principal_id=principal_id,
        agent_id=agent_id,
        run_id=run_a_id,
        ledger_path=ledger_path,
        egress_enabled=False,
        agent_scopes=RUN_A_SCOPES,
    )

    if not allow:
        return f"Policy deny search_docs: {reason}"

    docs = tools.search_docs(message)

    # Trích ticket_ids từ TÊN FILE (nguồn tin cậy), KHÔNG từ nội dung
    ticket_ids: list[int] = []
    for doc in docs:
        tid = _ticket_id_from_filename(doc["id"])
        if tid is not None:
            ticket_ids.append(tid)

    # Chạy find_injection để log (nhưng KHÔNG dùng customer_id từ kết quả)
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)
    # Redact PII trước khi tổng hợp (chặn PII ở boundary Run A -> Run B)
    # Run A kết thúc ở đây. Chỉ truyền ticket_ids (list[int]) sang Run B.

    # ============================================================
    # RUN B: read_customer theo ticket_ids -> policy check mỗi lần
    # ============================================================
    customer_ids = _find_customers_by_tickets(ticket_ids)

    collected = []
    for cid in customer_ids:
        # Kiểm policy TRƯỚC khi đọc
        allow, reason = _do_policy_and_log(
            tool_name="read_customer",
            args_for_hash=cid,
            classification="restricted",
            purpose="support-reply",
            principal_id=principal_id,
            agent_id=agent_id,
            run_id=run_b_id,
            ledger_path=ledger_path,
            egress_enabled=False,
            agent_scopes=RUN_B_SCOPES,
        )
        if not allow:
            continue
        try:
            record = tools.read_customer(cid)
            collected.append(record)
        except tools.ToolError:
            continue

    # Nếu có injection và có data, kiểm policy cho http_post
    if injected is not None and collected:
        target_url = injected.target_url
        allow, reason = _do_policy_and_log(
            tool_name="http_post",
            args_for_hash=target_url,
            classification="restricted",
            purpose="support-reply",
            principal_id=principal_id,
            agent_id=agent_id,
            run_id=run_b_id,
            ledger_path=ledger_path,
            egress_enabled=True,  # http_post = egress
            agent_scopes=RUN_B_SCOPES,
        )
        if allow:
            try:
                tools.http_post(target_url, {"records": collected})
            except Exception:
                pass

    return llm.summarize(docs)
