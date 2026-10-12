"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# --- Regex patterns ---

# EMAIL: standard local@domain.tld
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

# VN_CCCD: exactly 12 consecutive digits (Vietnamese citizen ID)
_CCCD_RE = re.compile(r"\b\d{12}\b")

# VN_PHONE: starts with 0, followed by 9-10 digits, optional spaces/dashes
_PHONE_RE = re.compile(
    r"\b0(?:[\s\-]?\d){9,10}\b"
)

# VN_BANK_ACCOUNT: 8-16 consecutive digits, usually preceded by context
# keywords like STK, số tài khoản, etc.
_BANK_CONTEXT_RE = re.compile(
    r"(?:STK|stk|Stk|số tài khoản|so tai khoan|tài khoản|tai khoan|bank.?account)"
    r"[:\s]*(\d{8,16})\b",
    re.IGNORECASE,
)
_BANK_STANDALONE_RE = re.compile(r"\b\d{8,16}\b")


def detect(text: str) -> list[dict]:
    """Detect PII entities in Vietnamese text using regex patterns."""
    entities: list[dict] = []
    # An explicit account label disambiguates 12-digit accounts from CCCD
    # and accounts beginning with 0 from phone numbers.
    bank_matches = list(_BANK_CONTEXT_RE.finditer(text))
    bank_spans = {(m.start(1), m.end(1)) for m in bank_matches}

    # 1) EMAIL — highest priority, won't collide with digit patterns
    for m in _EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    # 2) VN_CCCD — exactly 12 digits
    for m in _CCCD_RE.finditer(text):
        if (m.start(), m.end()) in bank_spans:
            continue
        entities.append({"type": "VN_CCCD", "start": m.start(), "end": m.end()})

    # 3) VN_PHONE — starts with 0, 10-11 digits total
    for m in _PHONE_RE.finditer(text):
        if any(m.start() < end and start < m.end() for start, end in bank_spans):
            continue
        # Normalize: strip spaces/dashes to count raw digits
        raw = re.sub(r"[\s\-]", "", m.group())
        if len(raw) < 10 or len(raw) > 11:
            continue
        entities.append({"type": "VN_PHONE", "start": m.start(), "end": m.end()})

    # 4) VN_BANK_ACCOUNT — context-based first, then standalone
    bank_positions: set[tuple[int, int]] = set()
    for m in bank_matches:
        start = m.start(1)
        end = m.end(1)
        bank_positions.add((start, end))
        entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})

    # Standalone: 8-16 digits not already matched by CCCD or PHONE or context bank
    for m in _BANK_STANDALONE_RE.finditer(text):
        s, e = m.start(), m.end()
        digit_str = m.group()
        digit_len = len(digit_str)
        # Skip if this range is already captured
        if (s, e) in bank_positions:
            continue
        # Skip if exactly 12 digits (CCCD) or 10-11 digits starting with 0 (phone)
        if digit_len == 12:
            continue
        if digit_len in (10, 11) and digit_str.startswith("0"):
            continue
        # Only count as bank account if 8-16 digits and not phone/cccd
        if 8 <= digit_len <= 16:
            entities.append({"type": "VN_BANK_ACCOUNT", "start": s, "end": e})

    # Remove duplicates: if same span has multiple types, keep higher-priority
    # Priority: EMAIL > VN_CCCD > VN_PHONE > VN_BANK_ACCOUNT
    # Remove overlapping lower-priority entities
    entities = _deduplicate(entities)

    return entities


def _deduplicate(entities: list[dict]) -> list[dict]:
    """Remove overlapping entities, keeping higher-priority ones."""
    priority = {"EMAIL": 0, "VN_CCCD": 1, "VN_PHONE": 2, "VN_BANK_ACCOUNT": 3}
    # Sort by priority (lower = higher priority), then by start position
    entities.sort(key=lambda e: (priority.get(e["type"], 99), e["start"]))

    result: list[dict] = []
    for entity in entities:
        # Check if this entity overlaps with any already accepted entity
        overlaps = False
        for accepted in result:
            if entity["start"] < accepted["end"] and accepted["start"] < entity["end"]:
                overlaps = True
                break
        if not overlaps:
            result.append(entity)

    return result


def redact(text: str) -> str:
    """Replace all detected PII entities with [REDACTED_<TYPE>] tokens."""
    entities = detect(text)
    # Sort by start position descending — replace from end to preserve offsets
    entities.sort(key=lambda e: e["start"], reverse=True)
    result = text
    for entity in entities:
        placeholder = f"[REDACTED_{entity['type']}]"
        result = result[:entity["start"]] + placeholder + result[entity["end"]:]
    return result
