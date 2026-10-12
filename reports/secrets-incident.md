# Secrets incident note

## Phát hiện

Dùng gitleaks v8.30.1 quét lịch sử git với config `.gitleaks.toml`:

```
gitleaks git --config .gitleaks.toml --redact --verbose .
```

Kết quả: **1 finding** — token giả `LAB24_FAKE_TOKEN=LAB24-DEMO-...` (đã redact).

- **Rule ID:** lab24-synthetic-token
- **File:** `lab-fake-secret.txt` (đã bị xóa khỏi HEAD nhưng còn trong lịch sử)
- **Commit:** `1bdd849`
- **Author:** VinUni AI20k Lab

Quét file hiện tại (`gitleaks dir`) cho kết quả sạch — file chứa token đã bị xóa ở commit sau.

## Đánh giá

Đây là token giả (LAB24-DEMO format), tạo ra cho bài tập, không phải credential thật. Tuy nhiên nếu đây là secret thật thì:

1. **Xóa file khỏi HEAD không đủ** — secret vẫn nằm trong lịch sử git, ai có access vào repo đều đọc được bằng `git show 1bdd849:lab-fake-secret.txt`
2. **Phải rotate/thu hồi token ngay lập tức** — đổi token ở service provider, revoke token cũ, kiểm tra audit log xem có ai dùng token bị lộ chưa
3. **Nếu cần xóa khỏi lịch sử** thì dùng `git filter-repo` hoặc BFG Repo-Cleaner, rồi force push. Nhưng rotate vẫn là bước quan trọng nhất vì không kiểm soát được ai đã clone repo trước đó

## Pin dependency và hook

- `.pre-commit-config.yaml` pin gitleaks ở `rev: v8.30.1`, dùng hook `gitleaks-system` với `pass_filenames: false`
- `requirements.lock` sinh bằng `pip-compile --generate-hashes`, mỗi package có hash SHA-256 để chống supply chain attack (dependency confusion, typosquatting)

**Pin dependency và hook không thay thế bước rotate khi secret đã lộ.** Hook chỉ ngăn commit mới chứa secret, không thu hồi được secret đã push. Lock file chỉ đảm bảo cài đúng package, không liên quan đến credential bị lộ. Hai biện pháp này là phòng ngừa, không phải khắc phục.
