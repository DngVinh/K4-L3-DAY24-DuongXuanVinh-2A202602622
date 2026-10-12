"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc CHECKPOINTS.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu một dòng còn trong file bị sửa mà không tính lại
        hash, nếu xoá/chèn giữa file làm đứt liên kết, hoặc thiếu reason.
        Chỉ kiểm tra file hiện có KHÔNG phát hiện được việc xoá dòng cuối
        hoặc viết lại cả file và tính lại chuỗi. Muốn phát hiện cắt đuôi
        phải lưu hash/số dòng cuối ở một nơi tin cậy bên ngoài file rồi
        đối chiếu. Bài lab không cung cấp mốc đó.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _compute_hash(entry_without_hash: dict) -> str:
    """SHA-256 của JSON canonical (sort_keys=True)."""
    raw = json.dumps(entry_without_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _get_last_hash(path: Path) -> str:
    """Lấy hash của dòng cuối cùng trong ledger, hoặc "0"*64 nếu file trống."""
    if not path.exists():
        return "0" * 64
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return "0" * 64
    last_line = content.splitlines()[-1]
    entry = json.loads(last_line)
    return entry.get("hash", "0" * 64)


def append(entry: dict, path: Path) -> dict:
    """Ghi 1 dòng vào ledger với hash chain."""
    path.parent.mkdir(parents=True, exist_ok=True)

    # Lấy hash dòng trước
    prev_hash = _get_last_hash(path)

    # Tạo bản copy, thêm prev_hash, tính hash
    record = dict(entry)
    record["prev_hash"] = prev_hash
    # Tính hash từ bản không có field "hash"
    record_for_hash = {k: v for k, v in record.items() if k != "hash"}
    record["hash"] = _compute_hash(record_for_hash)

    # Ghi ra file
    line = json.dumps(record, ensure_ascii=False)
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")

    return record


def verify(path: Path) -> bool:
    """Xác minh toàn bộ hash chain trong ledger."""
    if not path.exists():
        return True

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return True

    lines = content.splitlines()
    expected_prev = "0" * 64

    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False

        # Kiểm tra reason non-empty
        if not entry.get("reason"):
            return False

        # Kiểm tra prev_hash
        if entry.get("prev_hash") != expected_prev:
            return False

        # Tính lại hash và so sánh
        stored_hash = entry.get("hash")
        record_for_hash = {k: v for k, v in entry.items() if k != "hash"}
        recomputed = _compute_hash(record_for_hash)
        if stored_hash != recomputed:
            return False

        expected_prev = stored_hash

    return True
