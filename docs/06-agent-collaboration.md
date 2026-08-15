# サブエージェント協働計画

## 1. 方針

Lease lifecycle、DNS/browser integration、WFP、CI/CD、WPF UIは並行化できます。一方、Contracts、target schema、version、release workflowを複数担当が同時編集すると整合性が崩れます。

基本構成は次です。

- Primary integrator 1名
- 同時に最大3名のbounded subagent
- roleごとのdirectory ownership
- contract-first
- component作者とは別のintegration/compatibility review

小さい一file修正や密結合のcontract変更はsubagentへ分散せず、Primaryが一元処理します。

## 2. Roles

### Primary integrator

所有:

- `docs/` とADR
- `src/DistractionFirewall.Contracts/`
- target schemaの最終承認
- solution、central package/version、build property
- merge order、phase gate、release判断

責務:

- requirement/riskへ紐づくbounded taskを作る。
- Contractsとstate invariantsを先にfreezeする。
- 各branchのdiff/test/known limitationを確認する。
- YouTube固有logicがCoreへ漏れていないか統合時に検査する。

### Lease Core / Runtime agent

所有:

- `src/DistractionFirewall.Core/`
- `src/DistractionFirewall.ActivationService/`
- `src/DistractionFirewall.LeaseWorker/`
- `src/DistractionFirewall.Finalizer/`
- journal/time/IPC test

責務:

- immutable Lease Capsule、deadline、Named Pipe、authorization、Worker handoff、persistence、recoveryを実装する。
- WorkerをApp child/job/login sessionから独立させ、Task Schedulerのfixed actionで起動する。
- fake enforcerで通常CIをOS-independentに保つ。
- cancel/shorten/extend operationを追加しない。
- App/Activation Serviceの終了・削除をLease transition triggerにしない。
- Contracts変更は直接行わずPrimaryへproposalを返す。

### DNS / Browser agent

所有:

- `src/DistractionFirewall.DnsFilter/`
- browser policy adapter部分
- DNS/parser/browser integration test

責務:

- loopback DNS、target matcher、CNAME、upstream forwardingを実装する。
- adapter DNS snapshot/restoreとbrowser policy ownershipを実装する。
- malformed DNS fuzz corpusとprivacy testを残す。
- target definitionはread-only inputとして扱う。

### WFP / Windows Integration agent

所有:

- `src/DistractionFirewall.Enforcement.Windows/` のWFP部分
- `tests/Integration.Windows/` のWFP/reboot部分

責務:

- target-IP filter、IPv4/IPv6、TCP/UDP、TTL refresh、persistent ownershipを実装する。
- existing TCP/QUIC media flowを実測する。
- shared-IP collateralをevidence付きで報告する。
- catch-all network blockやkernel driverを独断で追加しない。

### CI agent

所有:

- `.github/workflows/ci.yml`
- `.github/workflows/dependency-review.yml`
- `.github/dependabot.yml`
- `eng/restore.ps1`、`eng/build.ps1`、`eng/test.ps1`

責務:

- stable `CI / gate`、locked restore、analyzers、test reportingを実装する。
- fake backendのsafe integrationを通常PRで実行する。
- `release.yml` とproduction credentialを変更しない。

### Packaging / CD agent

所有:

- `installer/`
- `.github/workflows/release.yml`
- `.github/workflows/network-e2e.yml`
- `eng/package.ps1`、`eng/verify-installer.ps1`、`eng/verify-release.ps1`

責務:

- App MSI、Runtime MSI、Burn、Service/DNS/task registration、clean-VM testを実装する。
- signing、SBOM、attestation、draft/publishを権限分離する。
- App package/root deletion independence、deferred Runtime uninstall、deadline後Finalizerを検証する。
- secret/certificateの実値をcode/chat/logへ出さない。

### UI agent

所有:

- `src/DistractionFirewall.App/`
- `tests/UI/`

責務:

- frozen Contractsに対してWPF/MVVM UIを実装する。
- Activation Serviceから返るtarget collectionを描画し、YouTubeをhard-codeしない。
- cancel/shorten/extend UIを作らない。
- accessibility、localization、unsafe state displayをtestする。

### Independent QA agent

原則read-only reviewまたはtest-only branchを使います。

- YouTube/browser/DNS/WFP/reboot matrixを実行する。
- 一般Web・Google serviceへのcollateralを確認する。
- deadline後のsetting復元とinstaller upgradeを確認する。
- App process kill、App MSI/root削除、Activation Service停止、normal reboot後もLeaseが継続することを確認する。
- Runtime/task/WFP等へのadministrator直接操作は既知非保証としてdocumentと一致するかだけ確認する。
- issueには再現手順、environment、evidence、severityを返す。

## 3. Parallel waves

同時稼働はPrimaryを含め最大4枠とします。

| Wave | Primaryと並行する3役 | 統合順 |
|---|---|---|
| P1-A Foundation | Lease Core/Runtime、DNS prototype、CI | Contracts → fake handoff → parser → CI |
| P1-B Enforcement | DNS/Browser、WFP/Windows、Packaging skeleton | DNS/browser → WFP → Runtime integration → two MSIs |
| P1-C Quality | Lease recovery、Packaging/E2E、Independent QA | deletion/recovery fixes → E2E → Phase 1 gate |
| P2-A UI | UI、Accessibility QA、Packaging/CD | IPC client → screens → MSI integration |
| P2-B Release | UI fixes、Independent QA、CD verification | fixes → full matrix → signed beta/stable |

## 4. Branchとworktree

agentごとに別branch/worktreeを使います。

```text
<workspace-root>\repo                         # primary integration
<workspace-root>\worktrees\123-lease         # feat/123-lease-runtime
<workspace-root>\worktrees\124-dns           # feat/124-dns-filter
<workspace-root>\worktrees\125-ci            # ci/125-foundation
```

規則:

- 一branchは一bounded issueと一owner role。
- assigned path外を編集しない。
- Contracts、central version/package、shared workflow interfaceはPrimaryだけが変更する。
- unrelated formatting/generated fileを変更しない。
- agent同士でforce pushやconflict上書きをしない。
- production signing、GitHub Environment、certificate operationをsubagentへ委任しない。
- real DNS/WFP testをdaily development machineで起動しない。

## 5. Contract-first

component実装前にPrimaryが次をfreezeします。

- `TargetDefinition` schemaとYouTube fixture version
- Lease/session state、App/Runtime install state、immutability invariants
- Named Pipe method、DTO、error code、protocol version
- `IEnforcer`、`IDnsFilter`、`IBrowserPolicy`、`ITimeAuthority`、journal boundary
- Lease Capsule、persistent artifact ownership、restore result
- App/Runtime installer component IDs、deferred uninstall intent、version source
- CI artifact manifest

変更proposal format:

```text
Problem:
Current contract:
Observed evidence:
Proposed change:
Compatibility/privacy impact:
Migration and tests:
```

Primaryがcontract/ADRを更新した後でconsumer taskを再開します。

## 6. Task template

```text
Goal:
In-scope paths:
Out-of-scope paths:
Relevant requirement/ADR:
Frozen inputs/contracts:
Acceptance tests:
Commands/environments allowed:
Expected evidence:
```

Windows network taskでは、成功結果に加えてoriginal setting、適用差分、rollback結果、test VM identifierをhandoffへ含めます。

## 7. Handoff

```text
Outcome:
Files changed:
Tests run and exact results:
Requirements/invariants covered:
OS settings touched:
Assumptions:
Known gaps / tests not run:
Suggested merge order:
```

Primaryは報告だけでなくdiff、repository status、test artifactを確認します。Lease Runtime、DNS parser、WFP、installer、release workflowは作者と異なるreviewerをmerge gateにします。

## 8. Escalation条件

次の場合はagentが実装を止めPrimaryへ戻します。

- cancel/shorten/extend APIが必要に見える。
- YouTube以外のtargetをVersion 1 scopeへ追加する必要がある。
- target-IP blockが広いGoogle serviceを壊す。
- 全outbound block、TLS MITM、kernel driverが必要になる。
- administrator tamper resistanceを暗黙に追加する。
- assigned scope外のshared contractを変える必要がある。
- development hostへreal WFP/DNS ruleを入れる必要がある。
- third-party dependency/license、external account、費用、production credentialが必要になる。

## 9. Merge gate

1. requirement/ADRへ紐づく。
2. path ownershipを守る。
3. local testとrequired CIが通る。
4. public contractにcompatibility testがある。
5. OS setting変更にはapply/restore/failure testがある。
6. privacy log boundaryを守る。
7. docsの保証/非保証と実装が一致する。
8. known gapをissue化し、Version 1 blockerか非対象かをPrimaryが明示する。

Phase完了は複数branchの結果を足し合わせず、protected mainの一つのcommitからfull test matrixとpackagingを再実行して判定します。
