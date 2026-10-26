# Changelog

All notable changes to ALICE-Container will be documented in this file.

## [Unreleased]

### Changed
- CI: `.github/actions/alice-siblings/action.yml` を共有の版 (ALICE-Analytics の main と同じ bytes) に揃える `.github/alice-siblings-private` に載せた非公開の隣を読み取り専用の鍵で clone できるようになった (この repository の隣はすべて公開なので、clone の仕方は変わらない)
- `IoUringCgroup::submit_and_wait` は file を開くだけで内容を書いていなかった 全 file の open → write → close を 3 回の `io_uring_enter` で行い、open / write / close の失敗と短い write を `OperationFailed` で返す (失敗時も開いた file は閉じる) `CgroupController::set_all_batched` は io_uring が使える時この経路で書く (従来は同期の書き込み) io_uring の ring が作れない時だけ個別の書き込みに戻る 非 Linux の stub に `queue_write` / `submit_and_wait` を足した
- Linux でだけ compile される code の clippy の指摘 (未使用の import、`match` を `if let` に、fd を開いたまま持つだけの field) を直した CI の test の最小の件数を 244 に (Linux の io_uring の試験 4 件と SQE の並びの試験 1 件を足した)
- `IoUringSqe::openat` が open flags を `len`、mode を `off` に入れていた kernel は mode を `len`、flags を `open_flags` から読むので、`O_WRONLY | O_TRUNC` が `O_RDONLY` として開かれていた liburing の `io_uring_prep_openat` と同じ並びにした

- `alice-sign` の git rev を 8a1b00d に上げた (HMAC-SHA256 の追加のみ、使っている API と byte 列は同じ)
- Licence: `AGPL-3.0` → `LicenseRef-Proprietary`
- CI: job `Clippy (all features)` を追加 固定した sibling で `cargo clippy --all-features --all-targets -- -D warnings` を走らせる (`scripts/preflight.sh` も同じ) `clone3` の unsafe な stub に `# Safety` 節を書き、定数の assert を `const` block にした
- 依存: sibling の ALICE-DB を `c791529`、ALICE-Crypto を `4ab0f0e`、ALICE-Analytics を `c87e6c7` に (deny の例外は `LicenseRef-Proprietary`)、`[patch.crates-io]` で alice-det-math を ALICE-DetMath `6384856` (0.5.2) の 1 つにする `db` / `crypto` / `analytics` feature を現在の API に合わせた: **破壊的変更** `ContainerDbSink` は blob store (`put_blob` / `scan_blob_prefix`) に書き、`query_container` は `Result` を返す (範囲は両端を含む)、鍵の導出と名前の hash は `alice_crypto::hash`、`Key::from_bytes`、analytics の型は `sketch` / `anomaly` module から import
- CI: `Test (public siblings)` job は sibling を workflow に書いた commit でなく `.github/alice-siblings` の固定 (security-audit と同じ) で checkout する 固定は各 sibling の現在の main (Analytics 79b5b4a / Crypto 31d525a / DB b3b8bd0 / Zip bf4cefa) に進め、`cargo test --features ffi,full,sync` は 239 passed で `MIN_PASSED` と同じ

### Security
- CI: `security-audit.yml` を追加 `.github/alice-siblings` に固定した実物の sibling (Analytics / Crypto / DB / Zip) と毎回新しい解決で `cargo audit` と `cargo deny --all-features check all` を走らせ、解決と deny の graph がこの crate と path の sibling を全て含むこと (0 件は失敗) を検査する 週次は日曜 02:29 UTC
- 解消に依存の更新が要る勧告は `scripts/advisory_holds.toml` の期限付きの保留 (2026-11-14 まで) とし、`scripts/advisory_hold_guard.py` が版と依存元の一致と期限を検査する: bincode 1.3.3 (unmaintained、alice-db 経由) それ以外の勧告は保留せず失敗する
- `deny.toml`: sibling の alice-crypto / alice-db を crate 単位の exception で許可、alice-crypto が固定 commit で取る ALICE-Sign の git source を許可

### Added
- CI: `Test (public siblings)` job 公開の path 依存 (ALICE-Analytics / ALICE-Crypto / ALICE-DB / ALICE-Zip) を固定の commit で隣に checkout し、`cargo test --features ffi,full,sync` を走らせる 通った試験が 239 件未満か、失敗した試験が 1 件でもあれば失敗 (`set -o pipefail` で cargo の終了状態も見る) 公開でない依存は checkout できないので失敗する `ci/**` の push でも走る `scripts/preflight.sh` は生成し直して同じ step を持つ

### Changed
- `signed_state_change` の Ed25519 (`KeyPair` / `PublicKey` / `Signature`) を `alice-sign` (MIT OR Apache-2.0、公開、git rev 8a1b00d) から取るようにした 型と鍵・署名の byte 列は同じ (これまでの依存先も同じ型を `alice-sign` から再公開していた) 公開の source だけで build できる

## [0.2.1] - 2026-03-04

### Added
- `ffi` — 45 `extern "C"` functions (`ac_ctr_*` prefix) for Unity/UE5/C consumers
- `bindings/unity/AliceContainer.cs` — 45 DllImport + 5 RAII handles
- `bindings/ue5/AliceContainer.h` — 45 extern C + 5 RAII types
- 12 FFI tests (null safety, config lifecycle, quota helpers, version)

### Fixed
- `examples/scheduler_demo.rs` — `min_quota_percent`/`max_quota_percent` → `min_quota_us`/`max_quota_us`

## [0.2.0] - 2026-02-23

### Added
- `container` — `ContainerConfig`, `Container` lifecycle (create, start, stop, destroy)
- `cgroup` — Direct cgroup v2 control via `/sys/fs/cgroup` (cpu, memory, io, pids)
- `namespace` — `NamespaceFlags`, `unshare(2)`, UID/GID mapping
- `rootfs` — `pivot_root(2)` based root filesystem isolation
- `scheduler` — Dynamic CPU quota adjustment for latency-sensitive workloads
- `io_uring` — (feature `io_uring`) io_uring async I/O support (Linux 5.6+)
- `clone3` — (feature `clone3`) `clone3(2)` with `CLONE_INTO_CGROUP` (Linux 5.7+)
- `psi` — (feature `psi`) Pressure Stall Information monitoring (Linux 4.20+)
- `analytics_bridge` — (feature `analytics`) ALICE-Analytics container metrics
- `db_bridge` — (feature `db`) ALICE-DB container state persistence
- `crypto_bridge` — (feature `crypto`) ALICE-Crypto container secret management
- `sync_bridge` — (feature `sync`) Container sync events
- `prelude` module for convenience imports
- 23 unit tests
