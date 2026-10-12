# DPIA-lite — đánh giá tác động trong bài lab

**Phạm vi:** bài tập dùng mock trên 26 hồ sơ synthetic tại `data/customers.json`. Đây là tài liệu học tập, không phải hồ sơ đánh giá tác động nộp cơ quan quản lý và không chứng minh tuân thủ pháp luật.

## Dữ liệu và mục đích

- Fixture có tên giả, ID khách trong lab, CCCD, số điện thoại, số tài khoản, email và `related_tickets`. Ticket chứa nội dung giả, được xem là đầu vào không tin cậy.
- Mock agent tổng hợp ticket hỗ trợ; Run B chỉ tìm hồ sơ theo ticket ID lấy từ tên file và quan hệ `related_tickets`. Policy kiểm tra principal, purpose, TTL và giao quyền scope trước khi gọi tool.
- Regex nhận diện/redact các định dạng CCCD, điện thoại, tài khoản và email đã biết. Không nhận diện tên; recall/precision trên bộ 118 nhãn synthetic không dự đoán chính xác thực tế production.

## Luồng, quyền truy cập và biện pháp

```text
corpus không tin cậy
        |
        v
Run A: search_docs -> ticket ID số từ tên file -> Run B
                                           |            |
                               customers.json       policy trước read
                                           |            |
                                           +----> ledger hash-chain
                                                        |
                      restricted hồ sơ --X--> http_post bị deny
```

Run B nhận `list[int]` và cờ boolean; không nhận văn bản ticket, customer ID hoặc URL do attacker trích ra. Summary chỉ nhận tài liệu đã redacted. `support_l1` bị deny truy cập restricted; `dpo` được đọc hồ sơ hợp lệ gắn với ticket. Cả hai đều không được gửi hồ sơ restricted ra sink.

Trong lab, ledger lưu hash arguments thay cho PII thô, nhưng `customers.json` vẫn là dữ liệu plaintext giả và ledger hash-chain một file không phát hiện việc xóa dòng cuối/viết lại toàn bộ. Bằng chứng replay theo 4 lure × 2 principal nằm trong [replay-verification.md](replay-verification.md); bằng chứng log/lịch sử ở [reports](.).

## Ánh xạ và giới hạn pháp lý

Luật Bảo vệ dữ liệu cá nhân 91/2025/QH15 Điều 3 khoản 2–4 nêu giới hạn phạm vi/mục đích, tính chính xác và biện pháp bảo vệ; Nghị định 356/2025/NĐ-CP Điều 19 nêu nội dung đánh giá tác động, gồm mục đích, loại dữ liệu, luồng, biện pháp và rủi ro. Luật Trí tuệ nhân tạo 134/2025/QH15 Điều 4 nêu nguyên tắc con người làm trung tâm, quyền riêng tư, kiểm soát/can thiệp và trách nhiệm giải trình. Nguồn đối chiếu là các bản ký chính thức liên kết trong [compliance-mapping.md](compliance-mapping.md).

Lab không thiết lập căn cứ xử lý, thu thập consent, xác minh danh tính người thật, thực hiện yêu cầu quyền chủ thể, quy trình lưu/xóa production, quản trị khóa, an ninh hạ tầng, hay đánh giá theo bối cảnh tổ chức. Cần đánh giá các nghĩa vụ và rủi ro đó riêng nếu triển khai xử lý dữ liệu thật. Không suy ra an toàn hoặc tuân thủ production từ kết quả mock.
