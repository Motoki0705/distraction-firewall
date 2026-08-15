# ADR-0003: App非依存のLease Runtimeを採用する

- Status: Accepted
- Date: 2026-08-15
- Related: [Product requirements](../01-product-requirements.md)、[Architecture](../02-system-architecture.md)、[Guarantee boundary](../03-security-threat-model.md)、[ADR-0002](0002-layered-youtube-enforcement.md)

> [!IMPORTANT]
> このADRは安定版のtarget designを記録します。初回alphaではApp/Runtimeのpackage分離、ACTIVE中のRuntime remove拒否、非破壊テストまでを実装しています。破壊的なWindows 11 VM evidence、`REMOVE_AFTER_COMPLETION`のproduction保存経路、期限後の自動remove、`UNINSTALL_PENDING`再試行、インストール済みinner PEの署名は未実装です。

## Context

開始済みのYouTube制限が、UI終了やユーザーが認識するApp本体の強制削除と一緒に終了するなら、製品の主要な利用価値を満たしません。一方、対象利用者はWindows内部のprocess、Scheduled Task、WFP filter、DNS、browser policyを調査し、Lease Runtimeを名指しで破壊する操作には十分な障壁を感じる、という前提を置きます。

Windowsのlocal administratorを技術的に封じることは目標にしません。保証するのはadministrator resistanceではなく、App lifecycleと開始済みLease lifecycleの非連動です。

## Decision

AppとLease Runtimeを別package、別install root、別process tree、別lifecycleにします。

```text
App package
  distraction-firewall.exe
  distraction-firewall-cli.exe
          │ PrepareLease / CommitLease
          ▼
Lease Runtime package
  Activation Service ── handoff ──► Lease Worker (SYSTEM task)
                                         │
                                         ├─ persistent browser policy
                                         ├─ persistent WFP filters
                                         ├─ DNS Filter coordination
                                         └─ deadline restore

App process/package/root deleted ────────► ACTIVE Lease is unchanged
```

具体的には次を採用します。

1. Activation Serviceはimmutable Lease CapsuleをProgramDataへ作成する。
2. initial enforcementを適用し、Task SchedulerからRuntime MSI所有の固定pathにあるLease WorkerをSYSTEMで起動する。安定版ではインストール済みWorker PEも署名するが、初回alphaではinner PE署名をまだ行わない。
3. WorkerがLease ID、manifest hash、artifact setを検証し、handoff ACKを返した後だけLeaseをACTIVEにする。
4. WorkerはAppのchild process、job object、interactive login sessionに所属せず、App binaryをloadしない。
5. App process終了、App MSI削除、App install root削除、Activation Service停止・削除をrelease eventとして扱わない。
6. persistent OS rulesとstartup/restart/periodic recovery/expiry taskにより、App不在とnormal rebootをまたいで同じdeadlineを維持する。
7. deadlineではWorkerまたはexpiry taskが製品所有規則を復元し、確認後にCOMPLETEDへ遷移する。

任意commandを隠れて実行するone-linerは採用しません。Task actionはRuntime MSIが所有する固定absolute pathとvalidated Lease IDだけで構成し、Runtimeの存在はWindows管理UIとdiagnosticsへ表示します。

## Package and uninstall behavior

App MSIとRuntime MSIをWiX Burn Setupで束ねます。

> [!IMPORTANT]
> 次の表は安定版のtarget behaviorを含みます。初回alphaで実装済みなのはpackage分離とACTIVE中のRuntime remove拒否までです。`REMOVE_AFTER_COMPLETION`、期限後の自動remove、`UNINSTALL_PENDING`再試行はまだ実装していません。現在は期限後にSetupを再実行してremoveします。

| 操作 | 仕様 |
|---|---|
| UI/App processを終了 | Leaseは変化しない |
| App install rootを削除 | Leaseは変化しない |
| App MSIを直接remove | Runtime、Capsule、tasks、Leaseは残る |
| ACTIVE中にSetup uninstall | Appをremoveし、Runtimeへ`REMOVE_AFTER_COMPLETION`を保存する |
| deadline到達 | 規則を復元してCOMPLETEDにする |
| deferred uninstallあり | 別FinalizerがRuntime MSIとSetup registrationをremoveする |
| App MSIだけ直接remove | intentを推測せず、期限後もRuntimeをinstalledのまま保つ |

Runtime uninstallに失敗しても再blockはしません。`UNINSTALL_PENDING`としてboot時に再試行し、block stateとinstall stateを混同しません。

## Version 1 guarantee boundary

次はVersion 1で保証します。

- UI close、UI/App process kill
- App MSIの通常remove
- App install rootの削除
- Activation Serviceの停止または削除
- sign-out、sleep、hibernate、normal reboot

次は明示的に保証しません。

- Lease Workerを特定してkillし、restart taskも停止または削除する
- Lease Runtime package/rootやLease Capsuleを直接削除・改変する
- WFP provider/filter、adapter DNS、browser policyを直接解除する
- Safe Mode、別OS、system clock tampering、OS再インストールを使う

この非保証範囲は欠陥の隠蔽ではなく、対象利用者と実装コストに基づく製品境界です。UIに解除shortcutは設けませんが、stealth、anti-kill、Protected Process、kernel driverは導入しません。

## Considered alternatives

### UIのchild background process

不採用です。UIのprocess tree、job、login session、install rootと寿命が結合し、App削除の独立性を保証できません。

### 一つのServiceと一つのMSI

不採用です。Appのuninstallがcontroller binary、state、rulesの削除へ連鎖しやすく、AppとLeaseのownership境界が曖昧になります。

### Appと独立したLease Runtime

採用します。App削除とLease終了を分離しつつ、期限後の正規restoreとdeferred uninstallを明示的に設計できます。

### stealth process、PPL、driverによるanti-kill

不採用です。local administratorへの対抗はVersion 1の要件でなく、Protected Process Lightを使う保護サービスには専用のELAM/signing要件があり、製品の複雑性とriskを大きく増やします。[Protecting anti-malware services](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)

## Consequences

### Positive

- ユーザーがAppだけを強制削除しても、開始済みLeaseはdeadlineまで継続する。
- UI/Appはenforcementのsingle point of failureでなくなる。
- local administratorへ対抗するkernel機構なしで、対象利用者に必要な摩擦を作れる。
- Appの再install後は既存Leaseをread-onlyで再表示できる。

### Negative

- 二つのMSI、Task Scheduler、Capsule、Finalizerのinstall/recovery testが必要になる。
- App削除後は状態UIがなく、再installまたはdiagnosticsで確認する必要がある。
- administratorがRuntime componentsを調査すれば解除できる。
- Worker/taskを同時に破壊した場合、期限後restoreが遅れ得るため保証外となる。

## Validation gates

使い捨てWindows 11 Home/Pro x64 VMで次を自動検証します。

> [!IMPORTANT]
> これは安定版へ進むためのrequired gateであり、初回alphaで完了済みのevidence一覧ではありません。現在のCIは非破壊テストとreadiness checkに限定され、実際のDNS/WFP/service/reboot、App root削除、MSI remove、deferred uninstallを通す破壊的VM evidenceは未取得です。

- ACTIVE handoff後、UI/App processをkillしてもYouTube blockとdeadlineが変わらない。
- App install root削除、App MSI直接remove後もRuntime/Capsule/tasksが残る。
- Activation Service停止・削除後もWorkerとpersistent rulesが残る。
- Worker単体crashではrulesが直ちに消えず、periodic taskが再起動する。
- normal reboot後に同じLease ID/deadlineをresumeする。
- deadline後にDNS/WFP/browser policyを復元し、COMPLETEDになる。
- Active中のSetup uninstallがAppだけをremoveし、deadline後にFinalizerがRuntimeをremoveする。
- testはRuntime/task/WFPを名指しで破壊するadministratorへの耐性を成功条件に含めない。
