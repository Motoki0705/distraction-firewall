# CI/CD・Windows 配布設計

## 1. 目標

CI/CD は Phase 1 の最初の commit から実装し、ブロックエンジンと並行して育てます。最終的な経路は次です。

> [!IMPORTANT]
> alphaのHosted CIはlocked restore、format、Release build、非破壊test、MSI/Burn静的contract、administrative-image/Burn payload検証、outer artifact checksum、3-package SPDX inventory、build-once candidate、GitHub build provenanceを実装しています。real DNS/WFP/browser/reboot E2E、installed inner PE署名、完全な依存関係SBOMは未実装です。one-UAC smokeはinstaller/service recovery、standard-user CLI/UI、uninstallを対象にし、Lease開始や実YouTube通信遮断を行いません。任意のAuthenticode署名が対象にするのはApp MSI、Runtime MSI、Setup EXEのouter 3 artifactだけです。

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
build-once release candidate
    │
    ▼
checksum / SBOM inventory / provenance / immutable artifact
    │
    ▼
one-UAC Windows 11 smoke of exact artifact ID/digest
    │
    ▼
annotated version tag vX.Y.Z + protected approval
    │
    ▼
same-byte draft GitHub Release（no rebuild）
    │
    ▼
separate publication approval → publish existing draft
```

「testした候補」と「公開する候補」をsource SHAだけで同一視しません。Actions artifact ID、archive digest、candidate manifest SHA-256、各asset SHA-256を結合し、tag workflowではbuildも署名もやり直さず、実機検証した同じbyte列をdraftへ昇格します。

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
distraction-firewall-1.0.0.candidate-manifest.json
distraction-firewall-1.0.0.candidate-subjects.sha256
distraction-firewall-1.0.0.hosted-evidence.json
distraction-firewall-1.0.0.provenance.bundle.json
distraction-firewall-1.0.0.windows11-smoke-promotion.json
distraction-firewall-1.0.0.windows11-smoke-promotion.provenance.bundle.json
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
    release-candidate.yml      # protected mainからbuild-once candidate生成
    release.yml                # tested candidateをtagのdraftへsame-byte昇格
    publish-release.yml        # review済みdraftの公開
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

## 5. Build once / promote same bytes Release

Release用バイナリはtag push時に再buildしません。候補生成、ローカル実機検証、draft昇格、公開を明確に分離し、実機で検証したbyte列とGitHub Releaseへ添付するbyte列を同一にします。

```text
protected main の exact commit
    │
    ▼
release-candidate.yml（1回だけ build / test / package / verify）
    │
    ▼
immutable Actions artifact
  ├─ App MSI / Runtime MSI / Setup EXE
  ├─ SHA-256 / SPDX distribution inventory
  ├─ candidate manifest / hosted evidence
  └─ GitHub build-provenance bundle
    │
    ▼
ローカル one-UAC smoke（同じartifact ID/digest/manifest）
    │
    ▼
protected Environment approval + annotated tag
    │
    ▼
release.yml（artifact IDでdownload、再buildせずdraftへ添付）
    │
    ▼
publish-release.yml（別のreview後にdraft解除）
```

### 5.1 候補を一度だけ生成する

`.github/workflows/release-candidate.yml` は `workflow_dispatch` だけを受け付けます。`main` から実行し、次の入力を明示します。

- `version`: `v` を付けないstrict SemVer
- `source_commit`: lowercase 40文字のcommit SHA

最初のjobはcheckout前にGitHub APIでdefault branchが `main`、branch protectionが有効、入力SHA・dispatch SHA・現在の `main` SHAが完全一致することを検証します。その後の全jobはこのgateへの `needs` pathを持ちます。

候補jobはlocked restore、format、Release build、test、win-x64 publish、MSI/Bundle package、installer contract、checksum/SPDX生成を行います。最後に次を封入して、一つのActions artifactとして90日保持します。

- 配布する3バイナリとSHA-256/SPDX inventory
- `distraction-firewall/build-once-candidate/v1` manifest
- Hosted CI検証evidence
- candidate subject checksum inventory
- `actions/attest` が生成するSLSA provenance bundle

manifestはsource repository/commit/ref/workflow path/run ID/attempt、各fileの名前・size・SHA-256、MSI ProductCode/PackageCode/UpgradeCode/ProductVersion、Bundle ProviderKey/UpgradeCode、detached Burn engine fingerprint、実測Authenticode statusを持ちます。candidate artifact自身のID/digestはupload後に初めて確定するため、manifest内ではnullです。これは自己参照digestの循環を避けるための仕様であり、artifact ID/digestとmanifest hashはGitHub API metadata、run receipt、外部provenance envelopeで結合します。

`upload-artifact` は `overwrite: false` とし、出力されたartifact ID、archive digest、manifest SHA-256をrun summaryへ記録します。Actionの `artifact-digest` 出力はprefixなしの64桁hexなので、workflow内で検証してからREST APIと同じcanonicalな `sha256:<64hex>` 形式へ正規化します。再runは別artifact IDになるため、実機検証と昇格は必ず一つのIDを選びます。

GitHub artifact REST APIはartifact ID、workflow run、expiry、archive digestを返します。[REST API endpoints for GitHub Actions artifacts](https://docs.github.com/en/rest/actions/artifacts) provenanceはfull SHAへpinした`actions/attest`で生成し、検証時はrepositoryだけでなくsigner workflow、source digest/ref、GitHub-hosted runnerも制約します。[Using artifact attestations to establish provenance for builds](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) [gh attestation verify](https://cli.github.com/manual/gh_attestation_verify)

package jobはrepository-level `WINDOWS_SIGNING_CONFIGURED` がexact `true` のときだけ `release-signing` Environmentへ直接bindし、そのapproval後に限りPFX secretへ到達します。Environment名はjobのdynamic `environment.name`で選び、unsigned alphaでは空文字列としてEnvironmentを参照しません。このため未作成の `release-signing` をunsigned runが保護規則なしで暗黙作成することも、不要な署名approvalを要求することもありません。署名を有効にする場合は、PFXとpasswordをrepository secretではなく `release-signing` Environment secretへ置き、Environmentの作成・保護・secret投入を終えてからrepository variableを `true` にします。

### 5.2 one-UAC Windows 11 smoke

ローカル準備処理は、GitHub APIでcandidate workflowのpath/event/head SHA/conclusionを検証し、artifactをID指定で一度だけdownloadします。API metadataの `digest` とdownloadしたZIPのSHA-256、candidate manifest、内包checksum、provenance envelopeを検証してから一括スクリプトを生成します。

Windows PowerShell 5.1のnative `>` はbinary ZIPを破損し得るため、download保存には `curl.exe -o` またはHTTP byte streamを使用します。`gh api > candidate.zip` はUbuntu promotion jobにだけ使用します。

非昇格の準備を完了した後、次の全処理を一つの昇格PowerShell内で行うため、UAC承認は候補ごとに原則1回です。

- 既知の旧Runtime障害があれば、固定manifestに従って限定repair/uninstall
- candidateのinstall
- service/ACL/failure actions、standard-user CLI、UIの検証
- inactive uninstallと残留物検証
- structured evidenceの保存

このsmokeは解除不能な制限を誤って開始しないため、LeaseのPrepare/Commitや実YouTube通信遮断を実行しません。したがってevidenceはinstaller/service recovery、standard-user CLI/UI、uninstallを証明しますが、YouTube network-enforcement E2Eの証明ではありません。

成功後、ownerは `windows-11-live-smoke-approval` Environmentへ次を設定します。

- `WINDOWS_11_LIVE_SMOKE_APPROVED_SHA` / `WINDOWS_11_LIVE_SMOKE_APPROVED_TAG`
- `RELEASE_CANDIDATE_RUN_ID`
- `RELEASE_CANDIDATE_ARTIFACT_ID`
- `RELEASE_CANDIDATE_ARTIFACT_DIGEST`
- `RELEASE_CANDIDATE_MANIFEST_SHA256`
- `WINDOWS_11_LIVE_SMOKE_ARTIFACT_ID`
- `WINDOWS_11_LIVE_SMOKE_ARTIFACT_DIGEST`
- `WINDOWS_11_LIVE_SMOKE_MANIFEST_SHA256`
- `WINDOWS_11_LIVE_SMOKE_EVIDENCE_SHA256`

`WINDOWS_11_LIVE_SMOKE_*` のartifact値はcandidate値と完全一致しなければなりません。Environment reviewerはローカルevidenceを確認してからdeploymentを承認します。promotion JSONの `workflowActor` はtag workflowを起動したactorであり、Environment reviewerではありません。reviewer identityとapproval時刻の正本はGitHub Deployment/Audit Logです。

### 5.3 同じbyte列をdraftへ昇格する

`.github/workflows/release.yml` はannotated `v*` tag pushだけで起動します。promotion gateはcheckout前に次をfail-closedで検証します。

- event SHA/tag、Environmentで承認したSHA/tag、現在のprotected `main` が完全一致
- tagがannotated tagで、最終的に同じcommitへ解決
- candidate runが `release-candidate.yml` / `workflow_dispatch` / `main` / successであり、head SHAがrelease SHA
- artifact IDがそのrunに属し、未expireで、name/digest/head SHAがreceiptと一致
- local smokeが同じartifact ID/digest/manifest SHAへbindされ、evidence hashが存在

draft jobはartifact IDのREST endpointからZIPをdownloadし、archive digest、flat exact inventory、candidate manifest、各file size/hash、配布checksum、candidate subject checksum、GitHub provenanceのsigner workflow/source SHA/refを再検証します。Environment gate後に生成したWindows 11 smoke promotion JSONも別の`actions/attest`呼び出しで証明し、offline provenance bundleと一緒に添付します。その後に限り、candidate directoryの既存fileを `gh release create --repo ... --draft --verify-tag` で添付します。checkout、compile、publish、package、署名、asset上書きは行いません。

Environmentはread-onlyの `promotion-approval` jobへ付け、`draft-release` はその検証済みoutputだけを `needs` 経由で受け取ります。Environment approvalとwrite jobが別attemptへ分離されないよう、approval時の `github.run_attempt` をoutputへ固定し、draft jobのattemptと完全一致させます。このためGitHubの **Re-run failed jobs** は古いapproval outputを再利用できずfailします。retry時は **Re-run all jobs** を選び、Environmentを再承認します。attestationはこのworkflow DAGによる間接approvalを示すもので、Environment設定そのものやreviewer identityを暗号学的に内包するものではありません。

draft notesはmanifestに基づくunsigned/outer-signed状態、SPDXが完全なdependency SBOMではないこと、same-byte promotion、one-UAC smokeの範囲、YouTube network E2E未実施を明記します。

### 5.4 draft reviewと公開

`.github/workflows/publish-release.yml` はprotected `main` からのmanual dispatchだけを受け付け、`release-publication` Environment approvalと `PUBLISH-REVIEWED-DRAFT` confirmationを要求します。current protected-main commit、annotated tag、draft状態、versionに対応するprerelease flag、title/tag/target commit、exact asset inventory、checksum、manifest、candidate artifact/run API metadata、candidate provenanceに加え、smoke promotion JSONの独立したprovenanceをrelease workflow・tag ref・commit SHAへ絞って再検証します。Actions artifactもIDで再downloadしてarchive digestを確認し、元の9 candidate fileとdraft上の9 fileをbyte比較します。candidate subject inventoryは期待する7 fileに固定し、manifestの各size/hashとhosted evidenceのrun bindingも再検証します。公開境界では11 assetすべてのAPI asset ID/name/size/digestを検証済みbyte列へ固定し、draftを再downloadしてbyte比較した直後に同じRelease IDとasset metadataを再取得します。各assetの最終API ID/size/digestを再download byteへ直接照合し、protected `main` とannotated tagのpeel結果ももう一度検証します。これによりdraft作成後または公開検証中にpayload、checksum/provenance inventory、promotion JSON、local evidence digestのいずれかを差し替えて公開gateを迂回することを拒否します。build操作はなく、この最終再照合後にだけ既存draftへ `--draft=false` を適用します。

GitHub RESTの複数GETとdraft解除を一つのatomic transactionにはできません。したがって最終再照合はrace windowを最小化する防御であり、repositoryのRelease/tagを書き換えられるmaintainer/adminはpublish完了までtrust boundaryです。`v*` tag rulesets、最小権限、監査log、publish前に有効化したImmutable Releasesを併用し、公開後のasset/tagをGitHub側でlockします。

運用開始前のmigrationは次です。

1. `main` へ新workflowとcontract testをmergeする
2. `windows-11-live-smoke-approval` Environmentのdeployment branch/tag policyをselected tag `v*` のみに限定し、required reviewer、admin bypass無効を設定する
3. `release-publication` Environmentを明示的に作成し、deployment sourceをprotected `main` branchだけに限定し、required reviewer、admin bypass無効を設定する。未作成のEnvironmentをworkflowから初めて参照すると保護規則なしで自動作成されるため、先にworkflowを実行してはならない
4. activeな `v*` tag rulesetを二つ作る。`release-tag-v-creation` はownerのexact User IDだけにcreation bypassを与え、`release-tag-v-immutability` はzero bypassでupdate/deletion/non-fast-forwardを拒否する
5. repositoryのImmutable Releasesを有効にする。この設定は有効化後に作成する新しいReleaseにだけ適用され、既存の `v0.1.0-alpha.1` Releaseには遡及しない。最初の新draft/tag作成前に有効化することを推奨し、少なくとも最初のpublicationより前にGET確認まで完了する
6. 署名を使う場合だけ `release-signing` Environmentを明示作成し、protected `main`だけを許可し、required reviewer、admin bypass無効、Environment signing secretsを設定する。今回のunsigned `v0.1.0-alpha.2` ではこのEnvironmentは不要であり、作成せず、repository-level `WINDOWS_SIGNING_CONFIGURED` を未設定またはexact `false` のままにする
7. 下記read-only API preflightをownerが実行し、JSON receiptをrelease evidenceとして保存する。期待値と一つでも違えばcandidate promotion/publicationを開始しない。`release-signing` の2 GETは署名有効時だけ必須
8. maintainerが一人の間は運用継続のためself-reviewを許可し、第二maintainer追加後はself-review禁止へ移行する。いずれの場合もevidenceを確認せず承認しない
9. `windows-11-live-smoke-approval` Environmentへ上記variableを設定する
10. protected `main` のexact SHAでcandidate workflowを一度だけ実行する
11. run receiptからID/digestを固定し、one-UAC smokeを行う
12. evidence review後にannotated tagをpushしてdraftを作る
13. draft assetsをreviewし、publication workflowを承認する

手順1のmerge直後から手順7のpreflightがすべて成功するまでを **外部設定freeze** とします。この間はcandidate/promotion/publication workflowを実行せず、`v*` tagをpushせず、draft作成やpublicationを開始しません。いずれかの設定または検証が失敗した場合はfreezeを維持します。

Environmentのdeployment policyは、`windows-11-live-smoke-approval` に `{"name":"v*","type":"tag"}`、`release-publication` に `{"name":"main","type":"branch"}` のexact requestを送ったreceiptを保存します。公式RESTのdeployment branch-policy GET response schemaはpolicyの `type` を返さず、nameだけではbranchとtagを独立に区別できません。そのためrequest/response receiptに加え、GitHub UIのSettings → Environmentsでlive-smokeがTag `v*`、publicationがBranch `main` であることを目視確認します。`can_admins_bypass` も公式REST write bodyで設定できないため、各EnvironmentのGitHub UIで **Allow administrators to bypass configured protection rules** をoffにして保存し、直後のEnvironment GETで `can_admins_bypass=false` を確認します。

`v*` 保護は次のexactな二つのrepository rulesetに分離します。bypassはruleごとではなくruleset全体に効くため、creationとimmutabilityを一つにまとめるとcreation主体がupdates/deletionもbypassできてしまいます。

`release-tag-v-creation`:

```json
{
  "name": "release-tag-v-creation",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [
    {
      "actor_id": 132140099,
      "actor_type": "User",
      "bypass_mode": "always"
    }
  ],
  "conditions": {
    "ref_name": {
      "include": ["refs/tags/v*"],
      "exclude": []
    }
  },
  "rules": [{"type": "creation"}]
}
```

`release-tag-v-immutability`:

```json
{
  "name": "release-tag-v-immutability",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": {
    "ref_name": {
      "include": ["refs/tags/v*"],
      "exclude": []
    }
  },
  "rules": [
    {
      "type": "update",
      "parameters": {"update_allows_fetch_and_merge": false}
    },
    {"type": "deletion"},
    {"type": "non_fast_forward"}
  ]
}
```

creation rulesetのbypassはexact owner `User` ID `132140099` だけとし、`RepositoryRole`、`OrganizationAdmin`、`Team`、`Integration`、`DeployKey` を追加しません。immutability rulesetは `bypass_actors: []` を必須とします。repository ownerはruleset設定自体を変更できるため最終的なtrust boundaryであり、各release前にruleset本体とhistoryを再取得します。

```powershell
# すべてGET。設定変更を行わないrelease preflight。
gh api -H 'X-GitHub-Api-Version: 2022-11-28' `
  repos/Motoki0705/distraction-firewall/environments/windows-11-live-smoke-approval
gh api -H 'X-GitHub-Api-Version: 2022-11-28' `
  repos/Motoki0705/distraction-firewall/environments/windows-11-live-smoke-approval/deployment-branch-policies
gh api -H 'X-GitHub-Api-Version: 2022-11-28' `
  repos/Motoki0705/distraction-firewall/environments/release-publication
gh api -H 'X-GitHub-Api-Version: 2022-11-28' `
  repos/Motoki0705/distraction-firewall/environments/release-publication/deployment-branch-policies
# 次の2 GETはWINDOWS_SIGNING_CONFIGUREDがexact trueのときだけ必須。
gh api -H 'X-GitHub-Api-Version: 2022-11-28' `
  repos/Motoki0705/distraction-firewall/environments/release-signing
gh api -H 'X-GitHub-Api-Version: 2022-11-28' `
  repos/Motoki0705/distraction-firewall/environments/release-signing/deployment-branch-policies
gh api -H 'X-GitHub-Api-Version: 2026-03-10' `
  'repos/Motoki0705/distraction-firewall/rulesets?includes_parents=true'
gh api -H 'X-GitHub-Api-Version: 2026-03-10' `
  repos/Motoki0705/distraction-firewall/immutable-releases
gh api -H 'X-GitHub-Api-Version: 2022-11-28' `
  repos/Motoki0705/distraction-firewall/actions/permissions/workflow
```

preflightは使用するEnvironmentごとにrequired reviewerが存在し、`can_admins_bypass=false`、期待したbranch/tag policyだけがactiveであることを確認します。policy typeは上記のrequest receiptとGitHub UI目視確認で補完します。署名有効時は `release-signing` がこの条件を満たし、PFX secretがEnvironment scopeにだけ存在することも確認します。今回のunsigned `v0.1.0-alpha.2` では `release-signing` GETを実行せず、repository-level signing variableがexact `true` ではないことを確認します。ruleset listから `release-tag-v-creation` と `release-tag-v-immutability` のIDを一意に得て各rulesetをGETし、target/enforcement/condition/rules/bypassが上記payloadとexactに一致することを確認します。Immutable Releasesは `enabled=true`、Actions default tokenは `read` を要求します。すべてが成功するまで外部設定freezeを解除しません。

2026-08-16のread-only監査では、`windows-11-live-smoke-approval` はrequired reviewerとadmin bypass無効が設定済みですがdeployment policyはnull、`release-publication` は未作成、repository rulesetsは空、Immutable Releasesは `enabled=false` でした。これはmigration前の既知blockerです。上記GETが期待値を返すまでReleaseを実行しません。

公開成功後、または候補を廃棄した後は、ownerがout-of-bandで `windows-11-live-smoke-approval` Environmentの上記10 receipt variableをすべて削除または次候補へrotateし、古い承認値を残しません。workflow tokenにはVariables write権限を与えず、この後処理をautomationへ委任しません。

candidate artifactがexpire/deleteされた、mainが進んだ、tagが違う、evidenceが別artifactを指す、Releaseが既に存在する、asset inventoryが変化した場合は再利用せずfailします。必要なら新しいcurrent `main` から新candidateを作り、もう一度one-UAC smokeを行います。

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
| candidate seal | `id-token: write`, `attestations: write`, `artifact-metadata: write` |
| promotion approval | `actions: read`, `contents: read`（candidate run/artifactとprotected `main` のGitHub API照合） |
| remote signing | `id-token: write` のみ必要に応じ追加 |
| draft promotion | `actions: read`, `attestations: read/write`, `artifact-metadata: write`, `id-token: write`, `contents: write` |
| reviewed publication | `actions: read`, `attestations: read`, `contents: write` |

追加規則:

- third-party Action は full commit SHA へ固定し、行末 comment に release version を記載する。
- `actions/checkout` は `persist-credentials: false`。
- untrusted code を実行する `pull_request_target` を禁止する。
- fork PR へ secret、OIDC signing、self-hosted runner access を渡さない。
- candidate workflowはprotected `main` のtrusted `workflow_dispatch`だけ、promotion workflowは`v*` tag pushだけ、publication workflowはprotected `main` のtrusted `workflow_dispatch`だけを受け付ける。
- `windows-11-live-smoke-approval` Environmentの承認SHA/tag、candidate run/artifact receipt、smoke evidence hashはowner/adminだけが手動設定し、workflowへVariables write権限を与えない。
- public PCへpermanent self-hosted runnerを登録せず、実機検証は監査済みlocal one-UAC batchで行う。
- `windows-11-live-smoke-approval`、署名有効時の `release-signing`、`release-publication` にrequired reviewerを置き、admin bypassを無効化する。Environment名をworkflowに書くだけでは保護にならず、out-of-band GET preflightを必須とする。
- promotion/publication workflowにはcheckoutとbuild/package commandを置かない。artifactはID指定で取得し、API digest、manifest、exact inventory、provenanceをfail-closedで再検証する。
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

- `release-tag-v-creation` で作成主体をexact owner User IDのみに限定
- `release-tag-v-immutability` はzero bypassとし、update/deletion/non-fast-forwardを禁止
- creation bypassがimmutabilityへ波及しないよう、二rulesetを統合しない
- Release workflow でも現在のprotected `main`との完全一致、annotated tag、versionを再検証
- 最初の新Release前にImmutable Releasesを有効化し、publish後のassetとtagを固定。既存の `v0.1.0-alpha.1` には遡及しない

## 10. Rollback と incident response

公開済み asset や tag を同じ内容で置換しません。

- candidate の不具合: artifactを昇格せず、修正後の新しいprotected-main SHAから新candidateをbuildしてone-UAC smokeをやり直す
- draft の不具合: assetを上書きせずdraftを破棄し、tag/versionを再利用しないforward releaseとしてやり直す
- stable regression: revert を含む新しい patch version を forward release
- vulnerable release: Security Advisory、必要なら release 削除、certificate/key incident 処理、新 version 公開
- tag名、artifact ID、artifact digestを再利用・読み替えしない
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
