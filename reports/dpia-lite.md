# DPIA-lite — Đánh giá tác động bảo vệ dữ liệu (phiên bản lab)

## 1. Dữ liệu xử lý

- **Loại:** dữ liệu cá nhân synthetic — CCCD (12 số), số điện thoại, số tài khoản ngân hàng, email, tên khách hàng
- **Chủ thể:** 26 khách hàng giả lập trong `data/customers.json`
- **Phân loại:** restricted (hồ sơ khách hàng), internal (nội dung ticket)

## 2. Mục đích xử lý

Agent tổng hợp ticket hỗ trợ khách hàng, tra cứu hồ sơ khách để phản hồi yêu cầu. Dữ liệu restricted chỉ được đọc khi principal có quyền (dpo), không được gửi ra ngoài hệ thống.

## 3. Luồng dữ liệu

```
corpus/*.md (untrusted) --> Run A: search_docs --> ticket_ids (int)
                                                       |
data/customers.json -----> Run B: read_customer <------+
                                  |
                            policy check --> deny http_post (restricted + egress)
                                  |
                            ledger.jsonl (ghi mọi quyết định)
```

- Run A chỉ đọc corpus, trích ticket ID từ tên file, không truyền free text sang Run B
- Run B tra customer qua `related_tickets`, gọi `read_customer` với policy check trước mỗi lần
- `http_post` bị deny bởi PEP vì `restricted + egress = deny`

## 4. Rủi ro đã xử lý

| Rủi ro | Biện pháp | Evidence |
|---|---|---|
| Prompt injection qua corpus | Trifecta split — Run B không đọc free text | `agent/runner.py`, `tests/test_split.py` pass |
| Rò rỉ PII qua sink | PEP deny egress khi data restricted | `reports/ledger.jsonl` dòng 23: http_post deny |
| Vượt quyền (support_l1 đọc restricted) | OBO check — principal scope intersection | `tests/test_obo.py` pass |
| Sửa audit log | Hash chain SHA-256 | `tests/test_ledger.py` pass |
| Secret lộ trong repo | Gitleaks hook + hash lock | `reports/secrets-incident.md` |

## 5. Giới hạn của mock

- **Không phải production:** dữ liệu synthetic, không có xác thực người dùng thật, `--as` chỉ là mô phỏng principal
- **Hash chain không chống xóa cuối:** kẻ tấn công có write access vào file ledger có thể xóa dòng cuối hoặc viết lại cả file mà không bị phát hiện nếu không có mốc tin cậy bên ngoài
- **PII detection dựa regex:** recall ~95%, không bắt được tên người hoặc PII dạng mới. Production cần NER model hoặc Presidio với model tiếng Việt
- **Allowlist cứng:** `127.0.0.1:10024` chỉ là safety net cho lab, không phải security control cho production
- **Không có mã hóa:** dữ liệu trong customers.json và ledger lưu plaintext
