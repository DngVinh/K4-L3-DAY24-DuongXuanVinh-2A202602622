# Verification — kết quả tự kiểm

## Kiểm tra nộp bài ngày 2026-10-12 (Bước 6)

- Chạy trên bản sao 91 file tracked trong `.day24-step6-20261012/`, dùng Python trong `.venv`, để fixture không reset `reports/sink.log` hay di chuyển corpus của repo gốc. Bản sao kiểm tra không được đưa vào commit.
- Lần đầu: `python -m pytest tests/ -q --basetemp=.pytest_tmp -p no:cacheprovider` → **33 passed in 1.56s**, không skip.
- Rà thêm rubric phát hiện scope rỗng được xem như bỏ qua giới hạn. Đã sửa `agent/policy.py`: luôn giao với `agent_scopes` và, khi delegation, luôn giao với `parent_scopes`; thêm regression test trong `tests/test_obo.py`.
- Sau sửa: `python -m pytest tests/ -q --basetemp=.pytest_tmp-final -p no:cacheprovider` → **34 passed in 1.33s**, không skip. Test OBO và split xác nhận `dpo` vẫn đọc khách hợp lệ, `support_l1` không đọc restricted, KH-000777 không bị đọc chỉ vì free text.
- `python -m agent.check_lure corpus/ticket-90*.md` → **4/4 lure sẵn sàng**, biến thể 4 kiểm hai file ghép.
- `python -m pytest tests/test_pii.py -q -s -p no:cacheprovider` → gold=118, pred=118, tp=112; precision=0.949, recall=0.949. Theo rubric, recall 85–95% tương ứng **7/10**, chưa đạt mức >95%.
- Ledger gốc: **23 dòng**, verify=True; mọi reason là chuỗi không rỗng; một `http_post` deny ở dòng 23; không có `read_customer` allow của `support_l1`.
- `attack-before.log` khớp nguyên record KH-000999 trong fixture synthetic; `attack-after.log` **0 byte**. Ba evidence đã được Git theo dõi dù có trong `.gitignore`.
- Gitleaks **8.30.1**: quét 12 commit lịch sử, exit 1 với đúng **1 finding** `lab24-synthetic-token` tại commit `1bdd849922156c868a5ee9293d68f5b72e242d2c`, là token giả dự kiến. Quét thư mục bản sao bài làm: **no leaks found**, exit 0.
- **Kiểm tra chưa hoàn tất:** `.venv/Scripts/pre-commit.exe run --all-files` bị Windows Application Control chặn, cả trong sandbox và dưới tài khoản sở hữu repo. Không tắt hay né kiểm soát; không coi việc chạy riêng Gitleaks là hook đã pass. Cần chạy lại pre-commit trong môi trường được phép trước khi xác nhận đủ toàn bộ bước nộp.
- Compliance mapping vẫn có các tham chiếu pháp luật chưa xác minh điều khoản; không tự chấm điểm tối đa cho mục này. Kết quả mock và dữ liệu giả không chứng minh hệ thống thật an toàn hoặc tuân thủ pháp luật.

Các kết quả dưới đây là bằng chứng của lần kiểm tra trước Bước 6.

## Test suite

```
$ python -m pytest tests/ -q
.................................                                        [100%]
33 passed in 0.57s
```

Tất cả 33 test pass, 0 fail, 0 skip.

## Chi tiết từng module

- **test_pii.py:** 2 passed. precision=0.949, recall=0.949 (gold=118, pred=118, tp=112)
- **test_policy.py:** 4 passed. restricted+egress deny, internal allow, public allow, OBO
- **test_obo.py:** 5 passed. support_l1 deny read_customer, dpo allow, delegation scope, TTL, runner boundary check
- **test_split.py:** 1 passed. KH-000777 không bị đọc (containment), customer hợp lệ vẫn đọc được
- **test_injection.py:** 8 passed. 4 biến thể × 2 principal, PII không ra sink
- **test_ledger.py:** 3 passed. hash chain, tamper detect, reason non-empty
- **test_supply_chain.py:** 3 passed. hook pin, lock hash, incident note
- **test_scaffold_dispatch.py:** 4 passed
- **test_check_lure_cli.py:** 3 passed

## Gitleaks

Phiên bản: v8.30.1

```
$ gitleaks git --config .gitleaks.toml --redact --verbose .
Finding: REDACTED (lab24-synthetic-token, commit 1bdd849)
leaks found: 1

$ gitleaks dir --config .gitleaks.toml .
no leaks found
```

## Ledger verify

```
$ python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"
True
```

## Before/After

- `reports/attack-before.log`: chứa record synthetic KH-000999 (CCCD, SĐT, STK)
- `reports/attack-after.log`: rỗng — PII không ra sink sau containment
