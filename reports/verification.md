# Verification — kết quả tự kiểm

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
