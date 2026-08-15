# 保証範囲とセキュリティ設計

## 1. 目的

Version 1は、Appの削除と制限Leaseの終了を連動させません。利用者がUIを閉じる、App processをkillする、App package/folderを削除する、Activation Serviceを停止する、という分かりやすい操作を行っても、独立したLease RuntimeがdeadlineまでYouTube blockを継続します。

一方、Lease Worker、Lease Runtime、Scheduled Tasks、WFP、DNS、browser policyを特定して個別に破壊する管理者には対抗しません。この差により、一般的なApp削除とWindows内部のenforcement解除の間に現実的な摩擦を設けます。

> [!IMPORTANT]
> ここでいう保証はVersion 1 stableのtarget boundaryです。初回alphaは主要componentと非破壊testを備えていますが、破壊可能なWindows 11でのinstall、App削除、DNS/WFP/browser、sleep/reboot、expiryの一連の証跡は未取得です。post-deadline Runtime/Bundle自動削除、installed inner PE署名、完全な依存関係SBOM、provenance/SBOM attestationも未実装です。

## 2. Version 1で保証対象にすること

- UI/AppはLease作成後のcontrollerでもsingle point of failureでもない。
- App process、App MSI、App install root、Activation Serviceの終了・削除でLeaseをCompletedにしない。
- Lease WorkerはAppのchild process、job object、interactive login sessionに属さない。
- persistent WFP/browser rulesはWorkerの一時停止だけでは消えない。
- startup/restart/expiry taskはApp packageと別に登録・保持する。
- normal reboot、sign-out、sleep、hibernate後も同じLeaseをresumeする。
- UI/CLI/API/notification/bundleにcancel/shorten/extendを作らない。
- deadline後はrulesをrestoreし、deferred uninstallがあればRuntimeも削除する。

## 3. 保証しないこと

- 管理者がLease Worker processを特定してkillし、restart taskも削除する。
- Lease Runtime package/root、Lease Capsuleを特定して削除する。
- WFP provider/filter、adapter DNS、browser machine policyを直接変更する。
- Task Scheduler、BFE等のWindows componentを停止・改変する。
- Safe Mode、別OS、custom VPN/VM/DoHを意図的に使う。
- cloud browser、remote desktop、relay、保存済みcontentを使う。

WindowsではAdministratorsがServiceへ強いaccess rightsを持ち、WFP engineのownership/DACLも回復できます。[Service Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)、[WFP Access Control](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control) したがって管理者全般を防ぐとは表現せず、どのcomponentを削除すると保証外になるかを明示します。

## 4. 想定利用者

- YouTubeを一定時間見ないと決める。
- UIのcancel buttonがなければ、その制約に従える。
- 思い直してAppを閉じる、通常uninstallする、App folderを削除する可能性はある。
- Lease Runtime、Scheduled Task、WFP filterを調査し、複数componentを順に破壊することには十分な心理的・技術的障壁がある。

このbehavior modelが本製品の有効性の前提です。隠蔽や解除手順の秘密性には依存しません。

## 5. Product invariants

1. `SessionState=ACTIVE` とApp/process/install stateは独立している。
2. ACTIVE後のtarget snapshot、deadline、rule hashはimmutableである。
3. Worker handoff完了前にAppへ成功を返さない。
4. App process、App MSI、Activation Serviceの終了eventをLease release triggerにしない。
5. UI、CLI、Named Pipe、notification、Setup bundleにcancel/shorten/extendがない。
6. Lease継続の正本はRuntime Capsule、persistent OS rules、Task Schedulerである。
7. Worker crash/killだけでpersistent WFP/browser rulesを削除しない。
8. deadlineまたは期限後repair以外の通常code pathからreleaseしない。
9. 製品所有artifactだけをrestore/deleteする。
10. DNS query、URL、page title、payloadをpersistent logへ保存しない。

## 6. Lifetime boundaries

```text
App lifetime
  WPF UI / CLI / App MSI / App directory
        │ StartLease only
        ▼

Lease lifetime
  immutable Capsule
  Lease Worker
  DNS Filter
  persistent WFP filters
  browser machine policies
  startup/restart/expiry tasks
        │ deadline
        ▼
  COMPLETED

Runtime installation lifetime
  KEEP
  or REMOVE_AFTER_COMPLETION → Finalizer → UNINSTALLED
```

Appを消してもLease lifetimeへtransitionを送らないことが最重要境界です。

## 7. Riskと対策

| Risk/operation | Design response | Guarantee |
|---|---|---|
| UI close/kill | WorkerはTask Scheduler起動で親子関係なし | 継続を保証 |
| App folder削除 | Runtimeは別install root | 継続を保証 |
| App MSI remove | Runtimeは別MSI/product | 継続を保証 |
| Active bundle uninstall | App削除 + Runtime deferred removal | 継続を保証 |
| Activation Service stop/delete | handoff後はWorker/Capsuleが正本 | 継続を保証 |
| sign-out/reboot | SYSTEM startup taskでresume | 継続を保証 |
| Worker crash/単発kill | persistent rules + restart/periodic task | best-effort継続 |
| Workerとrestart taskを両方削除 | cleanup/refresh停止 | 保証外 |
| Runtime root/package削除 | worker/recovery破壊 | 保証外 |
| WFP filter直接削除 | media IP block低下 | 保証外 |
| WFP必須targetの公開IPがactivation時に0件 | WFP mutation前にfail、既適用componentをrollback | `ActivationFailed`。ACTIVEにはしない |
| ACTIVE中にTTL-validな対象IPが0件 | reconcileをfail-closed、最後のowned filterを保持 | `Degraded`。失効IP filterがdeadlineまで残り得る |
| browser policy直接削除 | browser block低下 | 保証外 |
| adapter DNS直接変更 | DNS block低下 | 保証外 |
| existing YouTube flow | 観測済みtarget-IPへのWFP/reauthorization | 条件付きcoverage。未観測/shared CDN flowの即時切断は非保証 |
| YouTube endpoint変更 | DNS observation/catalog update | updateまで残余あり |
| shared CDN IP | per-rule IP policy/collateral test | warningあり |
| clock通常補正 | UTC + monotonic | 通常補正を吸収 |
| clock管理者改変 | early completion可能 | 保証外 |
| DNS Filter crash | periodic task restart、WFP/browserは残存 | 一般DNS停止の可能性 |
| expiry cleanup失敗 | independent expiry task + retry | RELEASE_PENDING |
| deferred uninstall失敗 | blockを再作成せず削除だけretry | inactive残留 |

WFPのpersistent objectはprocess session終了後も明示削除まで残せます。dynamic objectはowner session終了時に削除されるため、本設計ではLease enforcementの正本にしません。[WFP Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)

## 8. Component security

### App

- 通常ユーザー権限で実行する。
- raw WFP/DNS/browser ruleを渡さず、target IDとtimeだけを要求する。
- App directoryからRuntime DLL/configをloadしない。
- status取得不能時に「解除済み」と表示しない。
- reinstall後は既存Leaseへread-onlyで再接続する。

### Activation Service

- LocalSystemで動くcodeをvalidation、Capsule作成、initial apply、Task登録、handoffに限定する。
- external network listenerを持たずlocal Named Pipeだけを公開する。
- caller SIDをpipe tokenから確認する。
- Worker actionはRuntimeのfixed absolute pathとvalidated Lease IDに固定する。
- handoff後に自身が停止・削除されてもLeaseへrelease signalを送らない。

### Lease Worker

- Appからspawnせず、SYSTEMのTask Schedulerから起動する。
- fixed Lease IDだけをargumentに取り、arbitrary command/pathを実行しない。
- named mutex/lease lockで一instanceにする。
- Capsule manifest/hash、deadline、artifact ownershipを検証する。
- App process/pipe/fileをliveness dependencyにしない。
- deadlineまでrefresh/health/DNS coordinationを行う。

### DNS Filter

- loopbackだけでlistenする。
- allowed upstream resolverをCapsule snapshotへ固定する。
- DNS parserにsize、label、compression pointer、recursion、timeout制限を設ける。
- fuzz testする。
- full query logを保存しない。

### Scheduled Tasks

- SYSTEM、fixed executable、fixed argumentsで登録する。stable targetではaction先のinstalled PEを署名するが、初回alphaのinner PE署名は未実装である。
- startup、failure restart、periodic recovery、deadline expiryを分離する。
- multiple instance policyを `IgnoreNew` にする。
- task definition/ownershipをCapsuleへ記録する。

AdministratorsはTask Scheduler内のtaskをread/update/deleteできます。そのためtaskを探して削除する管理者は明示的に保証外です。[Task Scheduler security contexts](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)

### WFP/browser policies

- dedicated provider/sublayer/session GUIDでownershipを識別する。
- catch-all network blockを作らず、catalogが認めたtarget IPだけをblockする。
- browser policyはmachine scopeのYouTube patternだけを追加する。
- App MSIのcomponent ownershipに含めず、Runtime/Capsuleが所有する。

## 9. App deletionとdeferred uninstall

> [!IMPORTANT]
> この節のpost-deadline removalはstable向けtarget designです。初回alphaはActive Runtime removalをcapsule-store lock下でfail-closed拒否しますが、`REMOVE_AFTER_COMPLETION` のproduction write path、Runtime/Bundle自動remove、`UNINSTALL_PENDING` retryは未実装です。正本は [`installer/deferred-active-uninstall.status.json`](../installer/deferred-active-uninstall.status.json) です。

App deletionは次のいずれでもLease releaseを呼びません。

- process exit/kill
- UI crash
- folder deletion
- App MSI uninstall
- shortcut/registration deletion
- Activation Service stop/delete after handoff

Setup bundleからActive中にuninstallした場合だけ、Runtimeへ `REMOVE_AFTER_COMPLETION` intentを記録します。Appを先に削除し、Runtimeはdeadlineまで残します。

deadline後、Finalizerは次の順序を守ります。

1. browser/WFP/DNS artifactをrestore
2. YouTube解除と一般DNSをverify
3. SessionStateをCOMPLETED
4. Worker/DNSを終了
5. Runtime MSI/bundle registrationをremove

Runtime removal失敗時にYouTube blockを再適用しません。completed sessionとinstall cleanupを分離します。

## 10. Failure policy

| State | Failure | Behavior |
|---|---|---|
| PREPARED | App disappears | nonce expiry、Lease未開始 |
| ACTIVATING before handoff | Service crash | Capsule/artifactをreconcile、成功未通知 |
| ACTIVE | App/Activation Service disappears | 影響なし |
| ACTIVE | Worker disappears | rules残存、task restart |
| ACTIVE | DNS process disappears | task restartまで一般DNSも失敗し得る |
| ACTIVE | Runtime/taskを管理者が破壊 | 保証外、diagnostics不能の場合あり |
| RELEASING | 一部restore失敗 | RELEASE_PENDING、expiry/startup task retry |
| COMPLETED | Runtime uninstall失敗 | inactive UNINSTALL_PENDING、removeだけretry |

## 11. Privacy

保存するもの:

- Lease/session ID
- target ID/catalog version/rule hash
- activation/deadline/completion UTC
- state sequence/heartbeat/health/error
- product-owned artifact identifiers
- install intent

保存しないもの:

- 閲覧URL
- allowed DNS query一覧
- page title、search query、video ID
- network payload、Cookie、account情報

## 12. Supply-chainとtransparency

Lease Runtimeは存在を隠しません。

- Setup画面とdocumentでApp/Runtime分離を説明する。
- program一覧またはpending uninstall UIでRuntime残存を示す。
- binary、task、WFP objectに製品固有名とownership IDを付ける。Scheduled Taskはstableで署名済みfixed-path PEだけを起動し、WFP provider/sublayerは製品固有GUIDで識別する。
- stable targetではinstalled PEとApp MSI、Runtime MSI、Setup EXEをcode signする。初回alphaで任意署名・検証するのはouter 3 artifactだけで、inner PE署名は未実装である。
- SHA-256と配布artifact inventoryを公開する。完全な依存関係SBOM、build provenance、SBOM attestationはstable gateのtargetであり、初回alphaでは未実装である。
- stealth、process name偽装、system binaryへのinjection、自己隠蔽を行わない。

## 13. Version 1 test matrix

以下はrelease target matrixであり、初回alphaの完了済みevidence一覧ではありません。Hosted CIが実行するのは非破壊testで、real DNS/WFP/service/rebootを伴うnetwork E2Eは未実装のreadiness skeletonです。

Lease independence:

- Active後にUI/CLIをkill
- App folderをrename/delete
- App MSIをuninstall
- Activation Serviceをstop/delete
- Setup bundleでdeferred uninstall
- sign-out/sleep/hibernate/normal reboot
- Worker単発kill後のpersistent rules/restart
- expiry task単独release
- deadline後のRuntime自動uninstall
- finalizer failure/reboot/retry

YouTube enforcement:

- Chrome/Edge/Firefox/PWA/WebView2
- web/short URL/embed/API/media/static host
- IPv4/IPv6、TCP/QUIC、existing flow
- normal DNS/CNAME/cache、adapter switch
- general Web/Google collateral

Known non-guarantee verification:

- Runtime/task/WFPを特定して管理者が破壊できること
- custom VPN/VM/DoH、relay、saved contentがscope外であること

最後の項目は防止testではなく、保証文言と実装behaviorの一致確認です。
