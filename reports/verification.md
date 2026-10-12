# Verification — Bước 6

Ngày kiểm tra: 2026-10-12. Kết quả dưới đây chạy trên Python 3.14 trong GitHub Actions Linux, với các dependency ứng dụng cài bằng `requirements.lock --require-hashes`; không cần credential hay dịch vụ bên ngoài ngoài GitHub Actions.

## Kết quả rubric

- **Test suite:** `python -m pytest tests/ -q --basetemp=.pytest_tmp -p no:cacheprovider` — **50 passed**, 0 failed, 0 skipped.
- **PII:** `test_pii.py -s` — gold=118, pred=118, tp=118; precision=1.000, recall=1.000. Nhãn ngữ cảnh STK phân biệt tài khoản 12 số với CCCD; email, điện thoại và các lớp khác trong test vẫn được kiểm tra.
- **Lure:** `python -m agent.check_lure 'corpus/ticket-90*.md'` — **4/4**. Biến thể 904 chỉ vượt ngưỡng khi ghép hai file, có assertion riêng cho hai file đứng một mình.
- **Replay theo principal:** `tests/test_submission_evidence.py` phát lại bốn lure. Baseline bắt POST synthetic ở mock tool boundary; sau containment, cả hai principal có 0 lệnh `http_post`; `support_l1` có 0 lần đọc restricted, `dpo` vẫn đọc một hồ sơ hợp lệ; ledger của mỗi replay verify=True và không thiếu reason. Chi tiết trong [`replay-verification.md`](replay-verification.md).
- **Split/redaction:** Run B chỉ nhận ticket ID số và boolean, không nhận ticket text, customer ID hay URL; summary nhận bản đã redact. Test xác nhận KH-000777 không bị đọc chỉ vì free text attacker nhắc ID.
- **OBO:** principal, tool, purpose, TTL có timezone, agent scope và parent scope được fail closed; có regression test scope rỗng/thiếu, TTL sai hoặc hết hạn, principal lạ, purpose sai và delegation. `dpo` hợp lệ vẫn làm việc.
- **Ledger:** file nộp `reports/ledger.jsonl` có **23 dòng**, verify=True, mọi reason non-empty; dòng cuối chứa `http_post` deny với reason.
- **Baseline/after:** `reports/attack-before.log` chứa record synthetic KH-000999 từ baseline localhost; `reports/attack-after.log` **0 byte**. Test replay mới dùng mock boundary để không can thiệp sink/log của phiên lab đang chạy.
- **Supply chain/secrets:** Gitleaks **8.30.1**; Gitleaks chạy trên toàn bộ 14 commit và xác nhận đúng một finding `lab24-synthetic-token` ở `1bdd849922156c868a5ee9293d68f5b72e242d2c`. `gitleaks dir` trên nội dung bài hiện tại không có finding. `pre-commit run --all-files` — **Passed**. `requirements.lock` hash cho mọi package; workflow xác minh hash SHA-256 bản Gitleaks tải về trước khi dùng.
- **Compliance/DPIA:** đối chiếu ngày hiệu lực và điều khoản nguyên tắc của Luật 91/2025/QH15 Điều 3 khoản 2–4, Luật 134/2025/QH15 Điều 4, Nghị định 356/2025/NĐ-CP Điều 19 khoản 1–3 với PDF ký chính thức; mapping đánh dấu rõ mối liên hệ nguyên tắc và giới hạn của mock.

## Workflow thực thi

GitHub Actions: [Day24 verification — run 38206734216](https://github.com/DngVinh/K4-L3-DAY24-DuongXuanVinh-2A202602622/actions/runs/38206734216) trên commit `8562ee726557fbec4ee2a16696694da8a7362d4b` — conclusion **success**. Workflow đã cài package theo hash lock, chạy test/replay/PII/lure/ledger, chạy hook pre-commit, quét tree hiện tại và kiểm tra đúng finding synthetic duy nhất trong lịch sử. Máy Windows chặn launcher pre-commit cục bộ bằng Application Control; hook sau đó đã được chạy thành công trên runner GitHub Ubuntu, không đổi hoặc tắt kiểm soát máy.

## Điều kiện trượt và giới hạn

Evidence xác nhận `KH-000999` không ra sink sau contain; `KH-000777` không bị đọc từ free text; `support_l1` không đọc restricted; `parent_scopes` rỗng không cấp quyền. Bộ dữ liệu, tài khoản, token và sink là synthetic; scanner chỉ nhận diện token giả dự kiến từ lịch sử. Không có credential hay PII người thật được dùng. `--as`, policy lab, regex và hash chain một file không chứng minh có xác thực production, ngăn xóa đuôi ledger, hay tuân thủ luật trong hệ thống thật.
