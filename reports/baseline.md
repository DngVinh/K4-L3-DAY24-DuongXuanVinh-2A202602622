# Baseline — checkpoint 1

1. **Agent có identity riêng mỗi run chưa?** Chưa. `_naive_loop()` trong `agent/loop.py` (dòng 27–54) không tạo agent_id hay run_id. Mỗi lần gọi đều chạy cùng logic, không phân biệt ai ra lệnh, không có principal identity.

2. **Ai cho phép `http_post`?** Không ai kiểm soát. `_naive_loop()` gọi thẳng `tools.http_post()` (dòng 44) mà không qua policy check. Hàm `http_post` trong `agent/tools.py` (dòng 68–85) chỉ có allowlist cứng vào `127.0.0.1:10024` — đây là safety net của lab, không phải access control. Không có PEP, không có ledger ghi lại quyết định.

3. **Chứng cứ gửi sai PII?** Khi injection được phát hiện bởi `llm.find_injection()`, `_naive_loop()` đọc tất cả customer_id mà attacker nhúng trong document (dòng 37–41), rồi POST toàn bộ record chứa CCCD/SĐT/STK ra sink (dòng 44). Bằng chứng nằm ở `reports/sink.log` — file ghi mọi POST body tới sink. Không có audit trail hay ledger nào.
