# sds-scanner

`find_sds_in_dump.py` 的 Rust 版本：在 Chrome 主进程内存 dump 中定位 passkey 安全域密钥（SDS），单文件静态可执行，目标机器无需 Python 环境。

## 构建

在任何装有 Rust 工具链的机器上（rustup 安装本身不需要 Python）：

```bash
cargo build --release
# 产物: target/release/sds-scanner（Windows 下为 sds-scanner.exe）
```

把 `sds-scanner.exe` 和 `passkeys.jsonl` 拷到目标机器即可运行。若要从 macOS/Linux 交叉编译 Windows 版本，需安装对应 target 和链接器（如 `x86_64-pc-windows-gnu` + mingw-w64），最省事的方式仍是直接在 Windows 上 `cargo build --release`。

## 使用

参数与 Python 版一致：

```
sds-scanner <dump文件> [--jsonl passkeys.jsonl] [--ciphertext-hex <hex>]
            [--anchor-hex <hex> ...] [--window 8192] [--align 16] [--full-scan]
```

- 验证逻辑与 Python 版完全相同（HKDF-SHA256 + AES-256-GCM，AAD 为 `WebauthnCredentialSpecifics.Encrypted`），已用同一合成 dump 对拍，结果一致。
- 得益于 rayon 多线程，`--full-scan` 在 Rust 版是实际可用的：8MB dump（52 万候选）约 0.5 秒，数 GB 的全量对齐扫描约几分钟。
- 若目标机器的 dump 较大，先用默认锚点模式（秒级），不命中再放大 `--window` 或 `--full-scan`。
