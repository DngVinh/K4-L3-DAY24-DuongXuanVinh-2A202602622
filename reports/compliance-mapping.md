# Compliance mapping

Ánh xạ control trong bài lab tới quy định pháp luật và OWASP. Evidence trỏ tới file/dòng thật trong repo.

| Control | Evidence | Quy định liên quan |
|---|---|---|
| PII detection & redaction | [`agent/pii.py`](agent/pii.py) dòng 61-118: regex detect CCCD/SĐT/STK/email, redact trước khi data qua boundary | Luật 91/2025 (BVDLCN) — quyền bảo vệ dữ liệu cá nhân, xử lý phải có cơ sở pháp lý. NĐ 356/2025 hướng dẫn chi tiết biện pháp bảo vệ. *Chưa xác minh* điều khoản cụ thể từ văn bản gốc. |
| Policy enforcement (PEP) | [`agent/policy.py`](agent/policy.py) dòng 64-100: restricted+egress=deny, kiểm tra principal/scope/TTL | Luật 91/2025 — nguyên tắc mục đích, tối thiểu hóa dữ liệu. OWASP ASI-03 (Excessive Agency) — agent chỉ gọi tool được phép. |
| Trifecta split (containment) | [`agent/runner.py`](agent/runner.py) dòng 141-195: Run A chỉ đọc corpus, Run B tra customer qua related_tickets, không qua free text | OWASP ASI-01 (Prompt Injection) — containment kiến trúc ngăn attacker điều khiển agent đọc dữ liệu ngoài phạm vi. |
| OBO principal check | [`agent/policy.py`](agent/policy.py) dòng 78-90: kiểm tra principal, effective scopes = allowed_tools ∩ agent_scopes ∩ parent_scopes | Luật AI 134/2025 — yêu cầu giám sát và trách nhiệm khi AI hành động thay người. *Chưa xác minh* điều khoản cụ thể. OWASP ASI-04 (Insufficient Access Control). |
| Audit ledger (hash chain) | [`agent/ledger.py`](agent/ledger.py) dòng 49-73: SHA-256 hash chain, mọi dòng có reason, tamper-evident | Luật 91/2025 — yêu cầu ghi nhật ký xử lý dữ liệu. NĐ 356/2025 — biện pháp kỹ thuật đảm bảo tính toàn vẹn. |
| Deny egress kèm bằng chứng | [`reports/ledger.jsonl`](reports/ledger.jsonl) dòng 23: `http_post` deny, reason="du lieu restricted khong duoc phep egress ra ngoai", on_behalf_of="dpo" | OWASP ASI-03 — ngăn agent gửi dữ liệu nhạy cảm ra ngoài hệ thống. |
| Supply chain / secrets | [`.pre-commit-config.yaml`](.pre-commit-config.yaml): gitleaks pin v8.30.1. [`requirements.lock`](requirements.lock): hash cho mọi package. [`reports/secrets-incident.md`](reports/secrets-incident.md): incident note | NĐ 356/2025 — bảo mật chuỗi cung ứng phần mềm. *Chưa xác minh* điều khoản cụ thể. |

**Lưu ý:** Các trích dẫn pháp luật ở trên dựa trên tên văn bản và nguyên tắc chung. Chưa đối chiếu từng điều khoản cụ thể với văn bản gốc do giới hạn thời gian lab. Nơi chưa kiểm được đã ghi "chưa xác minh".
