# 2フェーズ開発計画

## 1. 開発方針

開発は二つのproduct phaseに分け、CI/CD、installer、testを両phaseと同時に実装します。

- Phase 1: YouTubeブロック機構、App非依存Lease Runtime、CLI、永続化、Windows統合を完成させる。
- Phase 2: WPF UI、時間入力、確認、Active画面、通知、accessibilityを完成させる。

> [!IMPORTANT]
> milestoneの成果物と完了条件はtargetであり、完了済み一覧ではありません。初回alphaは主要実装と非破壊test、App/Runtime MSI・Burnの静的contract、outer artifact inventory/checksumまで進んでいます。real DNS/WFP/browser/reboot E2E、post-deadline Runtime/Bundle自動削除、installed inner PE署名、完全な依存関係SBOM、provenance/SBOM attestationは未実装または未検証です。

Version 1の対象はYouTubeだけです。ただしCore、Contracts、target catalog、UI listは複数targetを扱える形にし、将来のサイト追加で状態機械やIPCを作り直さないようにします。

## 2. Dependency

```text
Requirements / ADR-0002 / ADR-0003
          │
          ▼
Generic TargetDefinition + Lease Contracts
          │
    ┌─────┼────────────┐
    ▼     ▼            ▼
 Lease    YouTube      CI/package skeleton
 state    catalog              │
    │     │                    │
    ├─────┼─────────────┐      │
    ▼     ▼             ▼      ▼
  DNS Filter       Browser policy    two MSIs
    │                   │            │
    └─────────┬─────────┘            │
              ▼                      │
        target-IP WFP ────────────────┘
              │
        independent Lease Runtime gate
              │
              ▼
        WPF UI against frozen RPC
              │
       Phase 2 release gate
```

## 3. Phase 1 — ブロック機構

### P1.0 Repository foundation

成果物:

- .NET 10 solutionとproject skeleton
- `global.json`、central package management、locked restore
- analyzers、nullable、warnings as errors、format rules
- initial `ci.yml`、Dependabot、Dependency Review、CodeQL
- `SECURITY.md`、`CONTRIBUTING.md`、CODEOWNERS、PR template
- common `eng/*.ps1` build/test scripts

完了条件:

- clean cloneからrestore/build/testできる。
- Pull Requestに安定名 `CI / gate` が出る。
- Core/App/ActivationService/LeaseWorker/Windows integrationのdependency方向をarchitecture testで検証できる。

### P1.1 Generic contracts、Lease state、YouTube catalog

成果物:

- `TargetDefinition` collectionとYouTube JSON schema
- `config/targets/youtube.json` とdomain/CNAME fixture
- immutable `LeaseManifest`、Lease Capsule、state machine
- session stateとApp/Runtime install stateの直交model
- UTC deadline、monotonic clock abstraction、reboot restore model
- versioned Named Pipe DTOとerror code
- fake clock、fake enforcer、fake target provider
- CLI `start/status/diagnose`

設計規則:

- Coreに `if target == YouTube` を置かない。
- UI/CLIから生のdomain/IP ruleをActivation Serviceへ渡さない。
- Active中のcancel/shorten/extend/remove contractを作らない。
- Lease開始時のtarget version/rule hash/deadlineを固定する。

test:

- 1分/12時間境界、指定時刻、DST/timezone、overflow
- double commit、timeout、replay、protocol version
- target normalization、label boundary、CNAME、duplicate rule
- 全state transitionとinvalid transition
- `AppInstallState` と `RuntimeInstallIntent` を変えても `ACTIVE` が変化しないこと

### P1.2 Activation Service、Lease handoff、永続化

成果物:

- Activation Service hostとcaller SID authorization
- `PrepareLease` / `CommitLease` / `GetStatus` / `WatchStatus`
- immutable Lease Capsule、journal、artifact ownership
- Task SchedulerによるSYSTEM Lease Worker起動とhandoff ACK
- startup/restart/periodic recovery/expiry tasks
- Worker/Finalizerのreconciliation、health/diagnostics
- deadline後のrestore retryと管理者向けrepair interface

test:

- Named Pipe ACL/caller identity
- activation各stepとhandoff境界のfault injection
- Activation Service/Worker crash、Capsule corruption、orphan artifact
- WorkerがAppのchild process/job/login sessionに属さないこと
- UI/CLI/App package/App root/Activation Serviceの終了・削除がActive Leaseに影響しないこと
- normal reboot後に同じLease ID/deadlineをresumeすること
- deadline後にrule解除を確認してCompletedになること

### P1.3 Browser policyとDNS Filter

成果物:

- Chrome/Edge/Firefox machine URL policy adapter
- supported browserのDoH/secure DNS policy adapter
- product-owned policy ledgerとcompare-and-swap restore
- Lease Runtime所有のloopback DNS Filter Service
- target exact/suffix/CNAME拒否
- original resolver forwarding
- adapter DNS snapshot、new adapter monitor、IPv4/IPv6 restore
- target answerをWFP backendへ通知するinterface

test:

- Chrome/Edge/Firefox、private mode、PWA、WebView2
- normal DNS、CNAME、cache、IDNA、malformed DNS/fuzz
- DHCP/static DNS、Wi-Fi/Ethernet切替、新規adapter
- enterprise policy/DNS conflictで既存値を壊さないこと
- DNS Filter crash/restartと一般DNS復旧
- deadline後にYouTubeのnegative cacheが不必要に残らないこと

### P1.4 WFP target-IP enforcement

現行alphaは公開target IPの必須address floorを実装しています。activation時に0件ならWFP mutation前に `ActivationFailed` とし、Active後に0件なら `Degraded` として最後のowned filterを保持します。YouTubeの代表seedは `www.youtube.com` ですが、動的な全 `*.googlevideo.com` endpointや既存TCP/QUIC flowの即時切断は実機未検証です。

成果物:

- dedicated WFP provider/sublayerとsession GUID ownership
- IPv4/IPv6、TCP/UDP target-IP block
- known host pre-resolution、DNS observation、TTL refresh
- `block_ip / dns_browser_only / observe` policy
- WFP transaction、persistent filter、startup reconciliation
- existing media flowを止めるALE/transport strategy

test:

- YouTube website、short URL、embed、API、static/media CDN
- 開始済みTCP/QUIC media flow
- DNS cache済み接続、直接target IP
- shared Google IPと一般Webのcollateral matrix
- BFE/Lease Worker restart、normal reboot、network change
- session終了時に自製品filterだけを削除すること

実OSのDNS/WFPを変更するtestは、日常開発機や通常PR runnerで実行せず、使い捨てWindows VMで行います。

### P1.5 Installer、CI/CD、Phase 1 gate

現行alphaではApp/Runtime二分割package、Active Runtime removalのfail-closed拒否、任意のouter 3 artifact署名、3-package SPDX inventory、checksumsを実装しています。`REMOVE_AFTER_COMPLETION`、deadline後のRuntime/Bundle自動remove、network E2E、inner PE署名、complete dependency SBOM、provenance/SBOM attestationは未実装です。

成果物:

- App MSI、Lease Runtime MSI、両者を束ねるWiX Burn Setup EXE
- install/repair/inactive uninstall、Active Lease中のdeferred Runtime uninstall
- App MSI/App root削除後もRuntime binary/Capsule/taskが残るpackage ownership
- GitHub-hosted fake/smoke CI
- isolated browser/DNS/WFP/reboot E2E
- SBOM、checksums、provenance attestation
- production code-signing backendとsigned prerelease

Phase 1完了条件:

- CLIからYouTubeを1分〜12時間または指定時刻までblockできる。
- UI/CLI/API/notification/通常uninstallerにearly cancel経路がない。
- Chrome/Edge/Firefox/PWA/WebView2の通常経路でYouTubeがblockされる。
- 観測済みtarget IPへの開始済みmedia flowが停止するか、次のmedia requestで停止することを実Windows VMで検証する。未観測/shared CDN flowを決定的に即時切断できるとは保証しない。
- 別Windows userにもmachine scope ruleが適用される。
- UI/CLI終了、App process kill、App root削除、App MSI削除、Activation Service停止・削除後も継続する。
- logoff、sleep/hibernate、Lease Worker crash/restart、通常reboot後も同じdeadlineで継続する。
- deadline後にDNS/WFP/browser policyが自動復元される。
- Active Lease中のSetup uninstallはAppを削除してもRuntimeを残し、deadline後にFinalizerがRuntime uninstallを完了する。
- 一般Web、download、WebSocket、主要Google機能への副作用が許容範囲である。
- Runtime/task/WFP等を直接破壊する管理者、custom VPN/DoH/VM、relay、保存済みcontentが非保証として正確にdocument化される。
- signed prerelease installer、SBOM、checksums、attestationを生成できる。

## 4. Phase 2 — Windowsアプリ層

Phase 2はPhase 1のfrozen Activation/Lease status contractを利用し、UIへprivileged logicを移しません。

### P2.0 App foundation

- WPF / .NET 10 / MVVM shell
- typed Named Pipe clientとstatus subscription
- mock Activation ServiceによるViewModel test
- Japanese resource、design token、accessibility baseline
- Activation Service unavailable、Lease degraded、release/uninstall pending表示

### P2.1 Targetと時間設定

Version 1のtarget listにはYouTube一件を表示します。hard-coded single screenにはせず、Activation Serviceが返すcollectionからcardを構築します。

- YouTube card、説明、影響範囲
- 15/30分、1/2/4/8/12時間presetと任意分数
- `指定時刻まで`、明日/日付/UTC offset表示
- input validationとresolved absolute deadline
- backend health、coverage warning

対象と時間は初期状態で未選択にし、誤開始を防ぎます。

### P2.2 確認とActive画面

最終確認:

- target、端末全体への適用、開始・終了、実時間
- YouTube関連hostによる副作用warning
- 「開始後はアプリから解除・短縮・延長・変更できない」
- App削除は保証するが、管理者によるRuntime/task/WFP等の直接破壊には対抗しないという簡潔なscope説明
- 明示checkbox。初期focusは「戻る」

Active画面:

- YouTube、deadline、remaining、backend health
- diagnosticsとApp closeだけ
- cancel/shorten/extend/change controlなし
- 開始、終了10分前、解除確認完了notification

### P2.3 Recovery、accessibility、E2E

- UI restartとactive state復元
- Activation Service disconnected、DNS failure、release/uninstall pending、repair required
- keyboard-only、focus order、UI Automation、高contrast、text scaling
- screen readerで秒ごとの過剰announcementをしない
- locale、12/24時間、DST/timezone
- double click、RPC timeout、multiple Windows users
- notification disabled、App close/reopen

### P2.4 Installer integrationとstable gate

- UI binary、shortcut、icon、notification registrationをMSIへ統合
- Phase 1 engine-only prereleaseからUI付きversionへのupgrade
- signed betaでfield test
- 同一release candidateでPhase 1のbrowser/DNS/WFP matrixを再実行
- signed `v1.0.0`、SBOM、checksums、attestation、immutable GitHub Release

Phase 2完了条件:

- target/time/confirmation/Active/completionのend-to-end flowが通る。
- UIのどこにもearly cancelまたはhidden overrideがない。
- Lease Capsule/Runtime stateと矛盾した「解除済み」表示をしない。
- accessibilityと日本語layout testが合格する。
- signed installerのclean install、upgrade、repair、inactive uninstall、deferred Active uninstallが合格する。
- YouTube以外のtargetをtest fixtureとして追加してもCore/IPC/UI listを変更せず表示・展開できる。

## 5. CI/CD maturity

次の表はphase gateの要求水準です。現行alphaの達成状況は冒頭のimplementation statusを正本とし、この表の「必須」を完了済みとは解釈しません。

| 能力 | P1.0 | Phase 1 gate | Phase 2 gate |
|---|---:|---:|---:|
| format/build/unit/contract | 必須 | 必須 | 必須 |
| fake Activation/Worker/enforcer integration | 骨格 | 必須 | 必須 |
| isolated browser/DNS/WFP/reboot E2E | 設計 | 必須 | 必須 |
| MSI/Setup | skeleton | App/Runtime二分割版 | UI統合版 |
| signing | backend調査 | signed prerelease | signed stable |
| SBOM/checksum/attestation | skeleton | 必須 | 必須 |
| installer upgrade | smoke | engine N-1→N | full N-1→N |
| UI/accessibility | なし | なし | 必須 |

## 6. Definition of Done

各issue/PRは次を満たします。

- 要件またはriskに紐づく受入条件がある。
- successだけでなくfailure、rollback、cleanupをtestする。
- public contract、OS setting、release behavior変更時はdocs/ADRを更新する。
- new dependencyの用途、license、maintenance、attack surfaceをreviewする。
- privileged codeとrelease workflowは独立reviewする。
- DNS/URLをpersistent logへ追加していない。
- local testとrequired CIが通る。
- packaging対象componentはinstaller smokeを更新する。
- 未実施testとknown limitationをhandoffに明記する。

## 7. 主なrisk

| Risk | 影響 | 対応 |
|---|---|---|
| YouTube endpoint変更 | 一部block漏れ | versioned catalog、fixture、release update |
| Shared CDN IP | 他Google機能を過剰block | per-rule IP policy、collateral E2E |
| DNS setting復元失敗 | 一般network障害 | compare-and-swap、journal、repair test |
| Existing QUIC flow | 開始後も再生継続 | WFP layer spikeとbrowser matrix |
| Browser policy差 | 未対応browserで漏れ | coverage diagnosticsとdocument |
| App deletion | Leaseも終了する実装退行 | package分離、dependency test、destructive E2E |
| Active bundle uninstall | 簡単なcancelになる | Appのみ削除、Runtimeをdeadline後までdefer |
| Lease Worker failure | block超過またはDNS停止 | persistent rules、scheduled restart/expiry、admin repair |
| Runtime/OS直接破壊 | early解除可能 | 明示的に許容しUIにはshortcutを置かない |
| Signing地域/費用 | stable公開不可 | eligibilityを早期確認しOV remote signing fallback |

## 8. 実装開始順

1. P1.0 repository foundation
2. P1.1 generic contractsとYouTube fixture
3. fake backendでLease stateとWorker handoffを完成
4. Browser/DNS/WFP adapterを個別にspike
5. 一つずつLease Runtimeへ統合し、各段階でrollback test
6. App/Runtime二分割MSIとdeletion/isolated E2E
7. Phase 1 gate後にWPF UI

OS network設定を扱う前にfake backendとrecovery contractを完成させることが、開発端末を不用意にofflineにしないための重要な順序です。
