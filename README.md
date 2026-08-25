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

## 验签预言机模式（--oracle-json）：直接找私钥本身

提供一份**真实登录断言**（浏览器抓包 `login/finish` 里的 `authenticatorData` / `clientDataJSON` / `signature`，b64url），扫描器会把每个候选 32 字节当作 P-256 私钥做离线验签：

```json
{"authenticatorData": "...", "clientDataJSON": "...", "signature": "..."}
```

```
sds-scanner <dump文件> --jsonl passkeys.jsonl --oracle-json real_oracle.json [--full-scan]
```

- 命中即输出私钥 scalar 和推导的公钥，模式为 `ecdsa-oracle`——**完全绕过 SDS**。
- 实现：预计算 u1/u2 后每个候选只需一次定基点标量乘，命中后再做完整验签复核。
- 性能：oracle 模式下全量扫描 415MB dump（2600 万候选）约 10 分钟。

## 其他新增

- 新增内置锚点：`KeychainApplicationKey`（短前缀）、`hw_protected`、key_version 的小端 u32（从 jsonl 自动提取）。
- live 模式现在统计并打印读取失败的内存块数，便于诊断扫描覆盖是否完整。

## Live 模式（仅 Windows）：直接扫描运行中的 Chrome

不生成 dump 文件，直接读取正在运行的 chrome.exe 进程内存：

```
sds-scanner.exe --live --jsonl passkeys.jsonl [--window 65536] [--anchor-hex <hex>]
```

- 实现：`Toolhelp32` 枚举 chrome.exe → `OpenProcess(PROCESS_VM_READ)` → `VirtualQueryEx` 枚举 `MEM_COMMIT + MEM_PRIVATE + 可读` 区域 → `ReadProcessMemory` 分块读取（16MB 块、64KB 重叠防锚点跨块）。
- 沙箱化的渲染进程是低完整性级别，同用户也 `OpenProcess` 失败，会被自动跳过；主进程（EnclaveManager 所在）可以打开。
- 权限要求与 procdump 相同：与 Chrome 同用户、同完整性级别即可，无需管理员。
- `--pid <PID>` 只扫描指定进程（主进程 = 命令行不带 `--type=` 的那个）。
- **`--watch` 持续监控模式**（解决时机问题，推荐）：先启动 `sds-scanner.exe --live --watch --jsonl passkeys.jsonl` 挂着，再去删 `passkey_enclave_state`、触发 passkey 登录、输 GPM PIN——SDS 一落进内存，下一轮扫描就能抓到，命中即自动退出。重扫间隔用 `--interval <秒>` 调整（默认 5）。
