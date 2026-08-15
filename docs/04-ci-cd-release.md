# CI/CD・Windows 配布設計

## 1. 目標

CI/CD は Phase 1 の最初の commit から実装し、ブロックエンジンと並行して育てます。最終的な経路は次です。

> [!IMPORTANT]
> 以下の大半はstable向けtarget designです。初回alphaのHosted CIはlocked restore、format、Release build、非破壊test、MSI/Burn静的contract、administrative-image/Burn payload検証、outer artifactのchecksumと3-package SPDX inventoryを実装しています。real DNS/WFP/browser/service/reboot E2E、installed inner PE署名、完全な依存関係SBOM、build provenance、SBOM attestation、自動Release publishは未実装です。任意のAuthenticode署名が対象にするのはApp MSI、Runtime MSI、Setup EXEのouter 3 artifactだけです。

```text
source code
    │
    ▼
Pull Request CI
format / lint / build / unit / contract / safe integration / security
    │
    ▼
protected main
    │
    ├── scheduled isolated network E2E
    │
    ▼
version tag vX.Y.Z
    │
    ▼
exact-tag rebuild and test
    │
    ▼
sign inner PE → build MSI/Setup EXE → sign outer packages
    │
    ▼
clean-VM install / upgrade / uninstall smoke
    │
    ▼
SBOM / SHA-256 / provenance attestations
    │
    ▼
draft GitHub Release → approval → immutable publish
```

stable targetでは「test が通った別のbinary」を公開せず、Release workflow内でexact tagから一度だけcompileしたpayloadを署名・包装・検証します。初回alphaの現行workflowは同じexact tagをtest jobとpublish jobで別々にbuildするため、source同一性はありますがbit-identicalなtested payloadの保証はまだありません。

## 2. 配布物

App削除後も独立して動くLease Runtime、WFP object、Task Scheduler、DNS/browser policyを導入するため、単体portable `distraction-firewall.exe` は正式配布物にしません。

インストール後の主な binary:

```text
distraction-firewall.exe             # WPF UI
distraction-firewall-activation-service.exe
distraction-firewall-lease-worker.exe
distraction-firewall-dns.exe         # Local DNS Filter
distraction-firewall-finalizer.exe
distraction-firewall-cli.exe         # diagnostics / Phase 1 control
```

stable targetのGitHub Release assets:

```text
distraction-firewall-setup-1.0.0-win-x64.exe
distraction-firewall-app-1.0.0-win-x64.msi
distraction-firewall-runtime-1.0.0-win-x64.msi
distraction-firewall-1.0.0.spdx.json
distraction-firewall-1.0.0.sha256
distraction-firewall-1.0.0-symbols.zip       # optional
```

App MSIとRuntime MSIを独立したWindows Installer productとし、Setup EXEはWiX Burnで両方を管理するuser-facing launcherとします。App MSIの削除がRuntime MSIのcomponent ownershipへ波及しない静的contractをtestします。破壊可能なWindows 11上のActive Leaseを使う保証証跡はまだありません。最初はWindows 11 x64のみを公開し、ARM64は実機E2Eと署名経路を用意してから追加します。

MSIX は service を含められますが、管理者 install、service 制約、machine DNS/WFP/registry ownershipを扱う初期版では MSI の方が明示的に管理しやすいため採用しません。[MSIX apps with services](https://learn.microsoft.com/en-us/windows/msix/desktop/managing-your-msix-deployment-targetdevices)

## 3. Build の再現性

リポジトリで次を版管理します。

- `global.json`: .NET 10 SDK feature band を固定
- `Directory.Build.props`: `ContinuousIntegrationBuild`、nullable、analyzers、warnings as errors、version source
- `Directory.Packages.props`: NuGet version の一元管理
- `packages.lock.json`: `dotnet restore --locked-mode`
- WiX SDK/tool version の完全固定
- PowerShell module/tool manifest と lock
- action reference の full commit SHA

.NET 10 は 2028 年 11 月までの LTS です。[.NET Support Policy](https://dotnet.microsoft.com/en-us/platform/support/policy) GitHub runner image 自体は更新されるため、`windows-2025` を明示しても SDK、WiX、SBOM tool、browser test version はリポジトリ側で固定します。

build script は `.github/workflows/*.yml` に埋め込まず、開発端末と CI が共通で呼べる `eng/*.ps1` に置きます。

```text
eng/
  restore.ps1
  format.ps1
  build.ps1
  test.ps1
  package.ps1
  verify-installer.ps1
  verify-release.ps1
```

## 4. GitHub Actions 構成

```text
.github/
  workflows/
    ci.yml
    network-e2e.yml
    dependency-review.yml
    release.yml
    codeql.yml                 # advanced setup が必要になった時点
  dependabot.yml
  CODEOWNERS
```

### 4.1 `ci.yml`

trigger:

- `pull_request`
- `push` to `main`
- `workflow_dispatch`

必須 CI workflow 全体には path filter を付けません。required workflow が skip され Pending のままになる事態を避け、job 内で軽量化します。[Required status checks troubleshooting](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)

```text
quality ────────────────────┐
unit-contract-architecture ─┼──► build-win-x64
safe-integration ───────────┘          │
                                      ▼
                           package-installers
                                      │
                                      ▼
                              installer-smoke
                                      │
                                      ▼
                                   ci-gate
```

`ci-gate` は `if: always()` で全依存 job の結果を判定し、branch ruleset の必須 check は動的 matrix 名でなく一つの安定名 `CI / gate` とします。

#### quality

- Markdown/link/style validation
- `dotnet restore --locked-mode`
- `dotnet format --verify-no-changes`
- Release configuration build、warnings as errors、nullable、.NET analyzers
- PSScriptAnalyzer
- WiX compile と MSI validation
- repository cleanliness と generated file drift の確認

#### unit-contract-architecture

- session state transition と invariants
- 1 分/12 時間境界、`until`、DST gap/fold、timezone、overflow
- YouTube exact/suffix/CNAME normalization と deterministic target expansion
- IPC serialization、version compatibility、idempotency
- journal recovery と clock abstraction
- architecture rules:
  - Core は UI/Windows implementation を参照しない
  - App は WFP API を直接参照しない
  - ActivationService/LeaseWorker/DnsFilter は App を参照しない
  - Lease WorkerはApp package/rootのfileをloadしない
  - privileged mutation はActivationService/LeaseWorker/Enforcementだけに置く
- TRX、Cobertura、test summary を artifact 化

coverage は可視化しますが、初期から単一の全体率だけを品質条件にしません。セッション状態、時間、target matcher、authorization には branch/property test の明示的な完了条件を置きます。

#### safe-integration

通常の GitHub-hosted runner のネットワークを変更せず、fake enforcer と in-process test DNS Filter で次を試します。

- Activation Service、fake Lease Worker、Named Pipe RPC
- pipe ACL と owner SID authorization
- `Prepare → Commit → Worker handoff → Active → Release` の contract
- Active 中に cancel/shorten/remove が存在しないこと
- App process/package stateをREMOVEDにしてもLease stateがACTIVEのままであること
- deferred uninstall intentとsession stateが独立していること
- crash point ごとの journal reconcile
- malformed/replayed request
- DNS target matcher、DNS parser、CNAME/upstream resolver abstraction

#### build-win-x64 / package-installers

- `win-x64` self-contained publish
- UI、Activation Service、Lease Worker、DNS Filter、Finalizer、CLIを一度だけbuild
- version/resource/icon/manifest、fixed Runtime path、Task actionを検証
- unsigned development App MSI、Runtime MSI、Setup EXEを作成
- binary と installer の version 一致を検証

single-file publish は service 更新、native library、署名、crash dump の検証後に component ごとに選びます。MSI 内部に複数 binary があること自体は問題ではないため、見た目だけを理由に single-file 化しません。

#### installer-smoke

stable targetでは、使い捨てのWindows 11 VMで次を行います。初回alphaのHosted CIはstatic installer contractと展開内容を検証し、下記の実install/Active Lease behaviorを完了済みevidenceとは扱いません。

- `/qn /norestart` install
- install directory と ACL
- App/Runtimeが別install root・別ProductCodeであること
- Activation Service登録、Task Scheduler definition、Service SID、failure actions
- UI/CLI の起動 smoke
- inactive 状態の repair/uninstall と残存物確認
- test Lease開始後にApp MSIを直接removeしてもRuntime/Capsule/tasksが残ること
- Active Lease中のSetup uninstallがAppだけをremoveし、Runtimeへdeferred uninstall intentを残すこと
- MSI log と診断を `if: always()` で保存

adapter DNS や real WFP filter を変更すると runner 自身の名前解決・Actions通信を失う可能性があるため、この job では fake backendを使います。

### 4.2 `network-e2e.yml`

実 WFP、adapter DNS、browser policy、再起動を操作する test は通常 PR から分離します。

現行 `network-e2e.yml` は意図的に失敗するreadiness skeletonです。DNS、WFP、service、firewall、Lease、uninstall mutationは一切実行せず、次のrunner lifecycle、watchdog、recovery proof、oracleが揃うまでpassing evidenceを生成しません。

trigger:

- trusted `workflow_dispatch`
- protected `main` の nightly/weekly schedule
- release candidate の明示呼出し

環境:

- 一 job ごとに破棄する Windows 11 x64 VM/JIT runner
- out-of-band の watchdog と VM timeout
- test 後に snapshot へ戻す。cleanup script だけへ依存しない
- fork PR code、release signing secret、publish token を入れない

test groups:

- WFP IPv4/IPv6、TCP/UDP/QUIC、existing flow、BFE restart
- Chrome/Edge/Firefox/WebView2 と local deterministic HTTP/HTTPS/QUIC fixtures
- 実 YouTube endpoint の定期 smoke（決定的 test の代用にはしない）
- normal DNS、browser DoH policy、CNAME/cache、adapter switch、DHCP/static復元
- target-IP WFP、existing TCP/QUIC media flow、shared-IP collateral
- sleep/hibernate/normal reboot、normal clock adjustment、expiry
- VPN/VM/custom DoHはcoverage情報を記録するが、Version 1の必須bypass gateにはしない
- install/upgrade、App deletion independence、deferred Active uninstall、expiry cleanup

公開 repository の永続 self-hosted runner は fork 経由の侵害面になるため使いません。必要なら一 job 後に破棄する ephemeral/JIT runner にします。[Self-hosted runner security](https://docs.github.com/en/actions/reference/runners/self-hosted-runners)

### 4.3 dependency/security workflows

- Dependabot: `nuget` と `github-actions` を weekly、minor/patch grouping、auto-merge なし
- Dependency Review: PR で high 以上の既知脆弱性を fail
- CodeQL: 公開 repository の default setup から開始し、C++/WDK または custom build が必要になったら advanced workflow
- Secret scanning と push protection: repository setting で有効化
- Action allowlist と、可能なら full-length SHA enforcement を有効化

[CodeQL default setup](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configure-code-scanning)、[Dependency Review](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/configure-dependency-review-action)

## 5. `release.yml`

### 5.1 trigger と version

- tag: `vMAJOR.MINOR.PATCH[-prerelease]`
- `workflow_dispatch`: 既存 tag の失敗再試行に限定
- tag、assembly、MSI、file version の一致を最初に検証
- tag commit が現在の protected `main` commit と完全一致することをGitHub APIで検証
- 同一 tag/release が存在すれば fail。asset 上書きはしない

alpha tagをpushする前に、maintainerは現在のprotected `main`のexact commitを実Windows 11で検証します。成功後、protected Environment `windows-11-live-smoke-approval` の次の変数をowner/adminがout-of-bandで設定します。

- `WINDOWS_11_LIVE_SMOKE_APPROVED_SHA`: lowercase 40文字のexact commit SHA
- `WINDOWS_11_LIVE_SMOKE_APPROVED_TAG`: 公開予定のstrict `v`-prefixed SemVer tag

`environment:` から未作成のEnvironment名を参照しただけでは保護は成立しません。GitHubはworkflow実行時にEnvironmentを自動作成できますが、そのEnvironmentにはprotection ruleも変数もありません。ownerは最初のtagをpushする前にSettingsで `windows-11-live-smoke-approval` を明示的に作成し、deployment tagを `v*` に限定し、required reviewerと「administratorによるprotection rule bypassを許可しない」を設定します。単独ownerのpersonal repositoryではtag pushを開始したowner自身が唯一のreviewerになるため、self-reviewは許可します。複数maintainer体制へ移行した時点でself-reviewを禁止し、tagをpushした人と承認者を分離します。

releaseごとの順序は、(1) 現在のprotected `main`のexact commitを実Windows 11でsource smoke、(2) 成功したSHAとこれから作るtagをEnvironment変数へ設定、(3) 同じcommitを指すannotated tagをpush、(4) Environment待機中のjobをrequired reviewerが承認、です。Environmentが未作成、両変数が空、形式不正、またはeventのSHA/tagと不一致ならapproval jobはcheckout前にfail-closedとなり、buildもdraft Release作成も開始しません。

tag pushで最初に動くGitHub-hosted approval jobは、untrusted tagをcheckoutせず、両変数をstepの `env` 経由で読みます。空値、形式不正、`github.sha` / `github.ref_name` との不一致、GitHub APIが返すdefault branch名・protection・現在の `main` SHAとの不一致をすべてfail-closedにします。workflow tokenは `contents: read` だけとし、Environment変数を自動更新する権限を与えません。`test`以下の全tag pipelineとdraft jobはこのjobの成功へ依存し、draft jobは承認済みSHA/tag outputも再検証します。

この承認はexact source commitのpre-tag実機smokeを証明するものであり、GitHub Actionsが再構築した配布artifactそのものの実機検証ではありません。draft作成後は、PRから起動できない既存のmanual self-hosted Windows 11 jobで添付artifactをdownloadしてinstall/service failure actions/diagnose/uninstall smokeを行い、証跡をreviewするまでReleaseを公開しません。

version 方針:

```text
Phase 1 prototype     0.1.0-alpha.N   # unsigned draft/prereleaseを許容
Phase 1 hardened      0.2.0-alpha.N   # signed prerelease
Phase 2 UI            0.9.0-beta.N
Stable                1.0.0+
```

### 5.2 job graph

stable targetのjob graph:

```text
validate-tag
    ↓
compile-and-test
    ↓
sign-inner-payload
    ↓
build-and-sign-installer
    ↓
verify-final-installer
    ↓
sbom-checksum-attestation
    ↓
create-draft-release
    ↓
release-publish environment approval
    ↓
publish-release
```

初回alphaの現行graphは `pre-tag maintainer live smoke → exact SHA/tag Environment approval → hosted approval gate → test → publish → package（任意のouter 3署名）→ hosted installer contract → checksum/SPDX inventory → draft Release → manual attached-artifact smoke` です。inner PE signing、complete SBOM、attestation、approval付きpublish jobはありません。draft noteはpre-tag source smokeだけが完了し、添付artifact smokeがpendingであることと、それが成功して証跡をreviewするまで公開禁止であることを明記します。

#### validate-tag

- strict SemVer と source version の一致
- `main` reachability
- stable は production signing configuration がなければ fail
- changelog/release note category の検証

#### compile-and-test

- exact tag を checkout
- locked restore、full build、unit/contract/safe integration
- release payload をこの run で一度だけ compile
- unsigned payload と manifest/hash を immutable workflow artifact で次 job へ渡す
- 過去の main CI artifact を流用しない

#### sign-inner-payload

このsubsectionは未実装のstable targetです。

- protected `release-signing` Environment
- UI、Activation Service、Lease Worker、DNS Filter、Finalizer、CLI、native DLL等のPEを先に署名
- RFC 3161 timestamp と SHA-256 を使用
- publisher subject、certificate chain、timestamp を `signtool verify /pa /all /v` で検証
- Release への write 権限を持たせない

SignTool は RFC 3161 timestamp をサポートします。[SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool) timestamp は証明書の有効期間後にも署名時点の検証を可能にするため必須です。

#### build-and-sign-installer

- 署名済みinner payloadからApp MSI、Runtime MSI、Burn Setup EXEを構築
- 両MSIとSetup EXEを最後に署名
- 外側の署名後に内容を変更しない
- package manifest と file hash を生成

#### verify-final-installer

stable targetでは、公開予定の署名済みpackageそのものをclean VMで検証します。初回alphaではouter packageのstatic verificationまでであり、次のclean-VM matrixは未完了です。

- publisher、chain、timestamp、全 inner PE signature
- silent/interactive install smoke
- App/Runtime別root、Activation Service/DNS/UI、tasks、ACL、WFP provider registration
- N-1 stable → N upgrade
- downgrade refusal
- repair、inactive uninstall
- Active Lease中のApp MSI直接remove、Runtime残存、deadline後Leaseだけが正常完了すること
- Active Lease中のSetup uninstall、Runtime残存、deadline後のRuntime自動remove
- version/ProductCode/UpgradeCode rules
- unexpected reboot と MSI log

#### sbom-checksum-attestation

このsubsectionはstable targetです。初回alphaはouter 3 artifactとSPDX inventoryのSHA-256、および3-package distribution inventoryだけを生成します。

- install payload から SPDX JSON SBOM を生成
- 最終署名後のApp/Runtime MSI、Setup EXE、SBOMへSHA-256 checksumを付ける
- GitHub build provenance attestation
- SPDX SBOM attestation

GitHub artifact attestations は binary provenance と SBOM attestation に対応します。[Artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)

#### draft / publish

- 現行draft jobは `contents: write` のみを持ち、署名credentialを持たない。
- 現行workflowは `gh release create --draft --verify-tag --notes` で明示的なalpha/stable-candidate noteとassetを添付する。
- approval付き `release-publish` job、attestation verification command、Immutable Releases有効化はstable targetであり未実装である。

GitHub は immutable release について、draft を作り asset をすべて添付してから publish する流れを推奨しています。[Immutable Releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)

## 6. Code signing

### 6.1 原則

- unsigned privileged installer を stable として公開しない。
- 長期 PFX と password を GitHub Secrets へ直接保存する構成を最終形にしない。
- remote signing/HSM と GitHub OIDC を優先する。
- signing job と Release write job を分離する。
- 同一 publisher identity を継続し、certificate rotation 手順を文書化する。

署名 backend の優先候補:

1. Microsoft Artifact Signing — 公開信頼の利用資格を満たす場合
2. CA 発行 OV certificate + remote signing/HSM
3. 適格な OSS であれば SignPath Foundation 等
4. Microsoft Store distribution を選択する場合の Store signing

Microsoft は Windows app の code-signing options を比較しています。[Code signing options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options) 設計時点で Artifact Signing の個人利用には地域制約があるため、日本在住の個人として利用可能かを契約直前に再確認し、利用不可なら OV remote signing を使います。

### 6.2 段階導入

- Stage 0（現行alpha）: CI、MSI、3-package SPDX inventory、checksumsまで。complete dependency SBOMとprovenance/SBOM attestationは未実装。unsigned draft/prereleaseを許容し、自己署名はdisposable test VMだけ
- Stage 1: production signing backend を導入し、signed prerelease を公開
- Stage 2: stable tag は署名、最終 installer smoke、approval がなければ fail-closed

新しい publisher は正しく署名しても SmartScreen reputation が直ちに確立するとは限りません。署名検証と reputation を同一視しません。[SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)

### 6.3 Version 1のnative範囲

Version 1はuser-mode WFP APIだけを使い、独自kernel driverを配布しません。将来、管理者耐性、vSwitch、Safe Mode等を要件へ戻す場合は、別ADRとdriver signing/CD設計を追加します。現在のRelease workflowへ未使用のdriver credentialやHardware Dev Center依存を入れません。

## 7. WiX / MSI 設計

WiX は SDK-style project とし、version を完全固定します。[Using WiX](https://docs.firegiant.com/wix/using-wix/) 採用 version ごとのライセンスと Open Source Maintenance Fee 条件を実装開始前と major update 前に確認します。[WiX OSMF](https://docs.firegiant.com/wix/osmf/)

次の `REMOVE_AFTER_COMPLETION` とpost-deadline removalはstable targetです。初回alphaはActive Runtime removalをfail-closed拒否しますが、intent永続化、自動remove、`UNINSTALL_PENDING` retryは未実装です。

- Windows Installer 標準の ServiceInstall/ServiceControl を優先する。
- arbitrary custom action は最小化し、必要なら rollback action を持たせる。
- App MSIとRuntime MSIでProductCode、UpgradeCode、install root、component ownershipを分離する。
- user-facing Setup、App MSI、Runtime MSIの所有関係を `installer/Bundle`、`installer/App`、`installer/Runtime` へ分離する。
- Activation Service/DNS Filterのaccount、Service SID、start type、failure action、DACLを明示する。
- Lease Worker、restart/expiry task、FinalizerはRuntime MSIだけが所有する。
- Program Files/ProgramData/registry/WFP object の ownership を installer manifest で管理する。
- Active Lease中のbundle uninstallはApp MSIだけをremoveし、Runtimeへ `REMOVE_AFTER_COMPLETION` を設定する。
- App MSIを直接removeしただけならRuntime uninstall intentは推測せず、deadline後もRuntimeをinstalledのまま保つ。
- Runtime MSIのupgrade/removeはACTIVE中に実行せずdeadline後へdeferする。
- UI を閉じるだけで service を止めない。
- major upgrade、repair、downgrade rejection、failed install rollback を test する。
- BurnはMSI prerequisiteとreboot requirementを管理する。

## 8. Workflow security

全 workflow の既定:

```yaml
permissions:
  contents: read
```

job ごとの追加権限:

| Job | 追加権限 |
|---|---|
| CI/test/package | なし |
| live-smoke approval | `contents: read`（protected `main` のGitHub API照合のみ） |
| remote signing | `id-token: write` のみ必要に応じ追加 |
| attestation | `id-token: write`, `attestations: write` |
| draft/publish | `contents: write` |

追加規則:

- third-party Action は full commit SHA へ固定し、行末 comment に release version を記載する。
- `actions/checkout` は `persist-credentials: false`。
- untrusted code を実行する `pull_request_target` を禁止する。
- fork PR へ secret、OIDC signing、self-hosted runner access を渡さない。
- Environment deployment branch/tag rule は `v*` と protected source に限定する。
- `windows-11-live-smoke-approval` Environmentの承認SHA/tagはowner/adminだけが手動設定し、workflowへVariables write権限を与えない。
- live-smoke approval jobはtag pushだけ、destructive self-hosted smokeはtrusted `workflow_dispatch`だけで実行し、PRから起動可能にしない。
- `release-signing` と `release-publish` に required reviewer を置き、admin bypass を無効化する。
- job ごとに timeout、workflow に concurrency を設定する。Release は `cancel-in-progress: false`。
- untrusted text を shell command や release script へ展開しない。

GitHub は Action の full SHA pinning を immutable reference として推奨しています。[Secure use of GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)

## 9. Repository rulesets

### `main`

- Pull Request 必須、direct push/force push/delete 禁止
- `CI / gate`、Dependency Review、CodeQL を必須
- conversation resolution、stale approval dismissal
- linear history
- `.github/**`、`installer/**`、ActivationService/LeaseWorker/Enforcement、security docs を CODEOWNERS 対象
- maintainer が二名以上になった時点で独立 approval を必須化

空 repository から一人で開始する段階で独立 approval を必須にすると開発不能になるため、当初は CI/ruleset を必須とし、最初の signed stable release 前に信頼できる第二 reviewer を追加します。

### `v*` tag

- 作成主体を maintainer/release automation に限定
- update/delete/force push 禁止
- Release workflow でも main reachability と version を再検証
- publish 後は Immutable Releases で asset と tag を固定

## 10. Rollback と incident response

公開済み asset や tag を同じ内容で置換しません。

- draft の不具合: publish 前に draft を破棄し、同じ source tag の扱いを監査して再実行
- stable regression: revert を含む新しい patch version を forward release
- vulnerable release: Security Advisory、必要なら release 削除、certificate/key incident 処理、新 version 公開
- tag 名を再利用しない
- MSI downgrade を拒否し、N-1 → N upgrade を毎回試験する

repository に `SECURITY.md`、脆弱性報告先、support policy、signing key rotation、catalog key revocation runbook を置きます。

## 11. Phase への組込み

### Phase 1 と同時に完成させるもの

- `ci.yml` と stable `CI / gate`
- unit/contract/architecture/safe-integration
- isolated `network-e2e.yml`
- App/Runtime二段MSI、Lease Worker/tasksを含むinstaller smoke
- unsigned artifact → signed prerelease までの Release skeleton
- SBOM、checksums、provenance
- Dependabot、Dependency Review、CodeQL、repository rulesets

### Phase 2 で追加するもの

- WPF ViewModel/input boundary/UI Automation test
- UI binary、shortcut、notificationをApp MSIへ追加
- UI ↔ Activation Service/Lease status IPC E2E
- App MSI削除後もRuntimeがActive Leaseを完了するE2E
- accessibility smoke と visual verification
- N-1 UI+engine upgrade
- signed beta から signed stable への release gate

CI/CD は各 phase の最後に後付けせず、各 milestone の完了条件として同時に実装します。
