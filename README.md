# Distraction Firewall

Windows 11 端末全体で YouTube への通常アクセスを一定時間ブロックする、自己制限用アプリケーションです。

ブロック開始時に、アプリは独立した期限付きLease Runtimeをbackgroundへ起動します。Version 1のtarget designでは、その後にUI/Appのprocess、directory、packageが消えても、Lease Workerとpersistent OS rulesが終了時刻までブロックを継続します。

> [!NOTE]
> 本製品はLease Runtime自体を探して終了したり、WFP・Task Scheduler・DNS・browser policyを個別に破壊したりする管理者には対抗しません。stable版で保証対象にするのは、UI終了、App packageの通常アンインストール、App directoryの削除、Activation Service停止がActive Leaseの終了と連動しないことです。初回alphaでは実装と非破壊testを行っていますが、破壊可能なWindows 11実機での保証証跡は未取得です。

## 設計方針

- 初期対象: YouTube のみ
- 対応対象: Windows 11 x64
- UI: WPF / .NET 10 LTS、通常は非昇格で実行
- 制御: Activation Serviceが期限付きLeaseを作り、独立したLease Workerへ所有権を移す
- ブロック: ブラウザ管理ポリシー、ローカル DNS filter、user-mode WFP の階層構成
- 独立性: App packageとLease Runtimeを別directory・別package lifecycleに分離
- セッション: 即時開始、1分以上12時間以下、または12時間以内の「指定時刻まで」
- 変更制限: 開始後は解除・短縮・延長・対象変更を提供しない
- 拡張性: Core は YouTube を直接ハードコードせず、将来 target catalog へ別サイトを追加できる
- 配布: MSIを内包したSetup EXEをGitHub Releaseで公開。stable版は署名必須
- 開発: Phase 1でブロック機構、Phase 2でWindows UI。CI/CDは両Phaseと並行開発

## ブロックの考え方

```text
App ── StartLease(deadline, YouTube) ──► Lease Runtime
                                        ├─ Lease Worker process
                                        ├─ persistent WFP filters
                                        ├─ machine browser policies
                                        ├─ local DNS filter
                                        └─ boot/expiry scheduled tasks

App/UI deleted ─────────────────────────► Lease remains ACTIVE
deadline ───────────────────────────────► COMPLETED / rules restored
```

HTTPSの通信本文を復号するTLS中間者方式は採用しません。YouTubeに関係するドメイン群と、DNSで確認した配信先を遮断します。他サイトの通常通信をNetwork Brokerへ強制する旧案は採用しません。

WFPが必須のtargetでは、TTL-validな公開target IPをseedまたはobservationから1件も得られない場合、activationはfail-closedで `ActivationFailed` になります。YouTubeの初期seedはexact host群と `www.youtube.com` であり、動的な全 `*.googlevideo.com` endpointを網羅しません。Active後に対象IPが0件になるとLeaseは `Degraded` となり、最後に所有していたWFP filterが観測回復またはdeadlineまで残る場合があります。

## インストールと使い方

1. 初回alpha以降の配布物は、[GitHub Releases](https://github.com/Motoki0705/distraction-firewall/releases) から `distraction-firewall-setup-<version>-win-x64.exe` とchecksumを取得します。
2. checksumを確認し、今後UIを使う同じWindowsアカウントでSetupを起動して管理者へ昇格します。導入後のUIはスタートメニューの「Distraction Firewall」から非昇格で起動できます。別の管理者アカウントの資格情報を使うover-the-shoulder installやSYSTEM配布はalpha版では非対応です。
3. YouTubeを選び、1分から12時間の長さ、または12時間以内の終了時刻を指定します。確認画面の警告に同意すると制限が始まります。
4. 開始後、UI/CLI/APIには解除・短縮・延長機能がありません。終了時刻になるとRuntimeが所有する規則を復元します。

Active Lease中にSetupをアンインストールすると、Appは削除されますがRuntimeの削除は拒否され、Leaseは継続します。現在のalpha版は期限後のRuntime自動アンインストールをまだ行わないため、期限後に同じSetupを再実行してアンインストールを完了してください。

## alpha版の状態

初回alphaとして扱う `0.1.0-alpha.1` は署名なしの先行版です。WindowsやSmartScreenの警告が表示され得るため、checksumと配布元を確認できる場合だけ管理者権限を与えてください。Hosted CIではlocked restore、format、Release build、非破壊の自動test、MSI/Burnの静的契約と展開内容、checksumを検証します。real DNS/WFP/service/rebootおよびreal WPF automation testは含みません。

次の項目は未検証または未完成であり、stable版のゲートを通りません。

- 破壊可能なWindows 11 Home/Pro x64実機でのinstall、再起動、sleep、別ユーザー、IPv4/IPv6、期限復元の一連の試験
- 開始前から確立済みの動的YouTube CDN接続を常に即時切断できることの実機証跡
- DHCPがActive Lease中に同一interfaceの上流DNSを変更した場合の追従
- 期限後のRuntime/Setup登録の自動削除
- installed inner PEのAuthenticode署名。現行workflowが任意で署名・検証するのはApp MSI、Runtime MSI、Setup EXEのouter 3 artifactだけです
- 完全な依存関係SBOM、build provenance、SBOM attestation。現行SPDXは配布artifact inventoryです

## ドキュメント

- [設計書の入口](docs/README.md)
- [プロダクト要件](docs/01-product-requirements.md)
- [システムアーキテクチャ](docs/02-system-architecture.md)
- [脅威モデルと保証範囲](docs/03-security-threat-model.md)
- [CI/CD・配布設計](docs/04-ci-cd-release.md)
- [2フェーズ開発計画](docs/05-development-plan.md)
- [サブエージェント協働計画](docs/06-agent-collaboration.md)
- [ADR-0002: YouTube階層型ブロック](docs/decisions/0002-layered-youtube-enforcement.md)
- [ADR-0003: App非依存のLease Runtime](docs/decisions/0003-independent-lease-runtime.md)

## リリース経路

```text
source code
    ↓
GitHub Actions
    ↓
format / lint / build / test / security scan
    ↓
Windows x64 build
    ↓
    optional outer-package signing / MSI・Setup EXE packaging
    ↓
    installer contract validation / checksums / artifact inventory
    ↓
GitHub Release
```

installed inner PE signing、完全な依存関係SBOM、provenance/SBOM attestationはこのalpha経路にはまだ含まれません。

端末全体のRuntimeとフィルタを導入するため、単体portable EXEは正式配布しません。Setup bundleはApp packageとLease Runtime packageを導入します。インストール後のUI実行ファイルを `distraction-firewall.exe` とします。
