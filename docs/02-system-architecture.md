# システムアーキテクチャ

## 1. 結論

Version 1はAppと制限Leaseを別ライフサイクルにします。

> [!IMPORTANT]
> 本文の図とlifecycleはVersion 1のtarget designです。初回alphaは階層enforcement、Lease lifecycle、App/Runtime package分離、Active Runtime removalのfail-closed拒否を実装し、非破壊testで検証しています。破壊可能なWindows 11でのDNS/WFP/browser/reboot証跡、post-deadline Runtime/Bundle自動削除、installed inner PE署名、完全な依存関係SBOM、provenance/SBOM attestationはまだありません。

```text
┌──────────────────── App lifecycle ─────────────────────┐
│ distraction-firewall.exe                              │
│ WPF UI / CLI                                          │
│        │ StartLease(YouTube, deadline)                 │
└────────┼───────────────────────────────────────────────┘
         ▼
┌────────────────── Lease Runtime lifecycle ─────────────┐
│ Activation Service                                    │
│   └─ create immutable Lease Capsule                    │
│   └─ apply persistent OS rules                         │
│   └─ register boot/restart/expiry tasks                │
│   └─ launch Lease Worker through Task Scheduler        │
│                                                       │
│ Lease Worker (independent background process)          │
│   ├─ browser machine policy                            │
│   ├─ local DNS Filter                                  │
│   ├─ persistent target-IP WFP filters                  │
│   ├─ refresh / health / deadline                       │
│   └─ completion / restore                              │
└───────────────────────────────────────────────────────┘

App process/package/directory deleted ──► Lease remains ACTIVE
deadline ───────────────────────────────► COMPLETED
```

AppはLease開始後のcontrollerではありません。Activation ServiceがLease Workerへ所有権を移した時点で、App process、App MSI、App directory、Activation Serviceの寿命はActive Leaseと無関係になります。

## 2. 保証境界

保証する削除・停止:

- WPF UI processの終了・強制終了
- App CLI processの終了
- App packageの通常アンインストール
- App install directoryの削除
- Activation Serviceの停止・削除
- sign-out、sleep、hibernate、通常reboot

これらはLease Worker、Lease Runtime package、persistent WFP rules、Scheduled Tasksを削除しないため、Leaseを終了させません。

保証しない操作:

- Lease Workerを特定してkillする
- Lease Runtime directory/packageを特定して削除する
- Lease restart/expiry taskを削除する
- WFP provider/filter、adapter DNS、browser policy、Lease Capsuleを直接変更する
- Safe Mode、別OS、custom VPN/VM等を使う

この境界は意図的です。一般利用者が「アプリを消す」操作と、Windows内部のLease構成要素を調査して個別に破壊する操作の間に摩擦を設けます。stealth process、anti-debug、anti-kill、自己隠蔽は使いません。

## 3. Packageとinstall root

Setup bundleは内部的に二つのpackageを導入します。

```text
App package
  C:\Program Files\Distraction Firewall\App\
    distraction-firewall.exe
    distraction-firewall-cli.exe

Lease Runtime package
  C:\Program Files\Distraction Firewall Lease Runtime\
    distraction-firewall-activation-service.exe
    distraction-firewall-lease-worker.exe
    distraction-firewall-dns.exe
    distraction-firewall-finalizer.exe
    targets\youtube.json

Lease state
  C:\ProgramData\Distraction Firewall\Leases\<lease-id>\
    lease.db
    manifest.json
    artifacts.json
```

App packageはLease Runtime packageを所有しません。App MSIのremove、App folderの削除、UI crashでRuntime binaryは消えません。

Runtime packageは通常のWindows componentとしてinstallし、存在を隠しません。stable targetではinstalled PEとouter packageを署名しますが、初回alphaの任意署名が対象にするのはApp MSI、Runtime MSI、Setup EXEのouter 3 artifactだけです。Windowsのprogram一覧またはbundle statusには、Active Leaseまたはdeferred uninstallがある間Runtimeが残っていることを表示します。

## 4. Components

| Component | 権限 | Lifetime | 責務 |
|---|---|---|---|
| WPF App | interactive user | 任意 | target/time入力、確認、status表示 |
| CLI | interactive user | command単位 | Phase 1 start/status/diagnose |
| Activation Service | LocalSystem、demand/auto start | install中 | request認可、Lease作成、initial rule適用、handoff |
| Lease Worker | SYSTEM task process | Active Lease | refresh、DNS coordination、deadline、restore |
| DNS Filter | LocalService相当 | Active Lease | target DNS拒否、allowed query forwarding |
| Expiry Finalizer | SYSTEM task process | deadline/repair時 | Worker不在時もreleaseを完了、deferred uninstall |
| WFP/BFE | OS | persistent | target-IP blockをprocess非依存で強制 |
| Task Scheduler | OS | persistent | boot/restart/expiryでRuntime processを起動 |

Lease WorkerはUIから直接spawnしません。Activation Serviceが固定pathと固定argumentsのTask Scheduler actionを登録・起動します。stable targetではaction先のinstalled PEを署名しますが、初回alphaのinner PE署名は未実装です。これによりWorkerはUIのchild process、job object、login sessionに属しません。

## 5. Lease Capsule

開始ごとに一件のimmutable Lease Capsuleを作ります。同時Active Leaseは一件です。

```text
LeaseManifest
  schema_version
  lease_id
  target_snapshot
  target_catalog_version
  rule_hash
  created_at_utc
  activated_at_utc
  expires_at_utc
  requested_duration
  boot_id
  monotonic_anchor
  install_intent

LeaseState
  PREPARED | ACTIVATING | ACTIVE | RELEASING | COMPLETED
  sequence
  last_heartbeat_utc
  health

Artifacts
  WFP filter GUIDs
  browser policy ownership
  adapter DNS snapshots
  task names
```

CapsuleはRuntime packageのProgramData領域に置き、App directoryを参照しません。Target snapshot、deadline、rule hashはACTIVE後に変更できません。

App/CLI/APIがCapsuleへ直接書くことはできません。管理者がProgramDataを直接書き換えることは保証対象外です。

## 6. StartLease transaction

```text
App                  Activation Service       Task Scheduler / OS
 │ PrepareLease             │                          │
 ├─────────────────────────>│ validate                │
 │ nonce/end/hash/warnings  │                          │
 │<─────────────────────────┤                          │
 │ CommitLease              │                          │
 ├─────────────────────────>│ persist ACTIVATING      │
 │                          ├─ create Capsule          │
 │                          ├─ snapshot DNS/policies   │
 │                          ├─ apply browser policy    │
 │                          ├─ apply persistent WFP ──>│
 │                          ├─ register tasks ────────>│
 │                          ├─ start Lease Worker ────>│
 │                          │  worker claims lease     │
 │                          │  verify target/general   │
 │                          │  persist ACTIVE          │
 │ ACTIVE/lease/end         │                          │
 │<─────────────────────────┤                          │
```

詳細:

1. caller SID、YouTube target、1分〜12時間、backend healthを検証する。
2. immutable target snapshotとresolved deadlineを作る。
3. CapsuleへACTIVATING intentionを同期永続化する。
4. original adapter DNSとbrowser policyをsnapshotする。
5. `exact_hosts` と明示的な `seed_hosts` を元のupstream DNSで解決し、公開IPだけを保護領域へ観測値として保存する。
6. browser rulesとpersistent WFP filtersを適用する。
7. Worker restart taskとdeadline expiry taskを登録する。
8. Task SchedulerからLease WorkerをSYSTEMで起動する。
9. WorkerがLease ID、manifest hash、artifact setを検証してownershipをclaimする。
10. YouTube拒否と一般site許可をprobeし、ACTIVEを永続化する。
11. Workerのhandoff acknowledgement後にだけAppへ成功を返す。

この時点以降、Activation ServiceはLeaseの継続に不要です。

## 7. Lease Worker lifecycle

Lease Workerはsingle-purpose executableです。shell commandや任意scriptを投下する「one-liner」ではなく、固定されたLease IDだけを受け取ります。installed binaryの署名はstable gateで要求するtargetであり、初回alphaでは未実装です。

Task Scheduler設定:

- Run as `NT AUTHORITY\SYSTEM`
- trigger: activation直後
- trigger: system startup
- restart on failure
- periodic recovery trigger
- multiple instances: `IgnoreNew`
- action: 固定absolute path + validated Lease ID
- working directory: Runtime install root
- network/battery条件で停止しない

Workerはnamed mutex/lease lockを取得し、二重起動なら新しいinstanceが終了します。periodic triggerは常駐Workerを毎回増やすためではなく、Workerがkill/crashした場合のbest-effort restartです。

Worker heartbeatが止まってもpersistent WFP/browser policyは残ります。DNS Filterが止まった場合はadapter DNSがloopbackのため一般DNSも失敗し得ますが、periodic taskがWorker/DNSを再起動します。

管理者がWorkerをkillし、さらにrestart taskを削除することは保証対象外です。

## 8. Persistent enforcement

制限をWorker processの生死だけに依存させません。

### Browser machine policy

- Chrome/Edge/FirefoxのYouTube URL blocklist
- 対応browserのDoHをOS DNS経路へ戻すpolicy
- AppでなくLease Capsuleがownershipを保持

[Chrome URLBlocklist](https://chromeenterprise.google/policies/url-blocklist/)、[Edge URLBlocklist](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/urlblocklist)

### Local DNS Filter

- adapter DNSをRuntimeのloopback filterへ向ける
- YouTube exact/suffix/CNAMEを拒否
- allowed queryをsnapshot済みresolverへraw socketでforward
- target addressをWFP refreshへ通知
- full DNS historyを保存しない

### Persistent WFP filters

- dedicated provider/sublayer/session GUID
- observed/pre-resolved YouTube target IPだけをIPv4/IPv6、TCP/UDPでblock
- `block_ip / dns_browser_only / observe` policyでshared-IP collateralを制御
- process terminationやBFE restart後も残るpersistent object

WFPのpersistent objectは明示削除まで存続し、dynamic session objectはowner session終了時に消えます。本設計はdynamic filterをLeaseの正本にしません。[WFP Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)

#### 必須WFP address floorとfail-closed動作

`ip_block_policy.mode=dns_observed` かつ `shared_address_action=block` のtargetでは、WFPを必須層として扱います。Commit時のDNS seedと既存のTTL-valid observationを合わせても公開IPv4/IPv6が0件なら、WFP adapterはownership ledgerやWFP policyを変更する前に失敗します。Windows複合adapterは先に適用したbrowser componentを逆順にrollbackし、Lease Runtimeは残りの永続artifactをreleaseします。したがってCommitは `ActivationFailed` となり、Leaseが `ACTIVE` になることはありません。release自体に失敗した場合だけ `RELEASING` に残り、cleanupを再試行します。

すでに `ACTIVE` のLeaseで全observationが失効した場合は、reconcileを失敗させてhealthを `Degraded` にします。このとき最後に所有していたWFP filterは削除せず、観測値が回復するかdeadlineでrestoreされるまで保持します。これはblockを弱めないためのfail-closed動作ですが、失効IPへのfilterがTTLを越えて残る可能性があり、shared CDN collateralとの明示的なtrade-offです。

初期seedはsuffixを列挙できないため、target catalogに具体的な代表名を `seed_hosts[]` として宣言します。YouTubeは少なくとも `www.youtube.com` をseedしますが、動的に命名される全 `*.googlevideo.com` endpointの列挙・網羅を意味しません。seed hostは必ず同じtargetの `exact_hosts` または `suffix_hosts` に包含されなければなりません。

WFP filterは観測済みIPへの新規connectとoutbound transportを遮断しますが、hostname別に既存TCP/QUIC flowを安全に列挙・強制終了する機能は持ちません。共有CDN上の未観測IPやOS/WFPのreauthorization timingに依存するため、開始済み再生の即時停止を決定的保証とは表現しません。実Windows VMでのexisting-flow E2Eはrelease gateとして別途必要です。

HTTPS本文は復号せず、browser URL host、DNS domain、target IP metadataだけを扱います。

## 9. YouTube TargetDefinition

Coreは複数targetのcollectionを扱い、Version 1はYouTube一件だけを配布します。

```text
TargetDefinition
  stable_id
  display_name
  catalog_version
  exact_hosts[]
  suffix_hosts[]
  cname_suffixes[]
  seed_hosts[]
  browser_url_patterns[]
  ip_block_policy
  known_collateral[]
```

YouTube web UI、short URL、embed、API、media CDN、YouTube固有assetをJSON fixtureで版管理します。新targetはdefinition/test/UI resource追加で拡張し、Lease protocolを変更しません。

## 10. App削除とuninstall scenarios

> [!IMPORTANT]
> 次の表はstable向けtarget behaviorを含みます。初回alphaではApp/Runtime分離とActive Runtime removal拒否を実装していますが、`REMOVE_AFTER_COMPLETION` の永続化、deadline後のRuntime/Bundle自動remove、`UNINSTALL_PENDING` retryは未実装です。Active中にremoveを試みた場合はRuntimeを残し、期限後にSetupを再実行します。

| 操作 | App | Lease Runtime | Active Lease |
|---|---|---|---|
| UIを閉じる/kill | 停止 | 稼働 | 継続 |
| App folderを削除 | 破損/削除 | 別rootで稼働 | 継続 |
| App MSIをremove | 削除 | 登録維持 | 継続 |
| Activation Serviceをstop/delete | 利用不能 | Worker/taskは独立 | 継続 |
| Setup bundleをActive中にuninstall | App削除、削除予約 | completionまで残る | 継続 |
| sign-out/sleep/hibernate | UI停止 | resume | 継続 |
| normal reboot | UI任意 | startup taskでresume | 継続 |
| Lease Workerだけkill | 影響なし | periodic taskが再起動を試行 | persistent rulesは残る |
| Runtime folder/task/WFPを個別削除 | 影響なし | 破壊 | 保証外 |

「Appを消した」の範囲はApp process、App package、App rootです。Runtimeまで関連fileとして探索・削除するthird-party force uninstallerは保証対象外です。

## 11. Deferred uninstall

Session stateとinstall lifecycleを分離します。

この節は未実装のpost-deadline removalを含むtarget designです。現行alphaのcapability statusは [`installer/deferred-active-uninstall.status.json`](../installer/deferred-active-uninstall.status.json) を正本とします。

```text
SessionState        = ACTIVE
AppInstallState     = INSTALLED | REMOVED
RuntimeInstallIntent = KEEP | REMOVE_AFTER_COMPLETION
RuntimeInstallState  = INSTALLED | UNINSTALLING | UNINSTALLED
```

Active中にSetup bundleのuninstallを選ぶ場合:

1. bundleがActivation Service/Lease CapsuleへActive状態を確認する。
2. `RuntimeInstallIntent=REMOVE_AFTER_COMPLETION` を永続化する。
3. App MSI、shortcut、UI registrationを削除する。
4. Runtime MSI、tasks、Worker、DNS/WFP/browser rulesは残す。
5. userへ「削除予約。deadline後にRuntimeも自動削除」と表示する。
6. program一覧にはRuntimeまたはpending bundle entryを残す。

deadline後:

1. Worker/Expiry FinalizerがRELEASINGへ遷移する。
2. browser policy、WFP filter、adapter DNSをownership確認してrestoreする。
3. target解除と一般DNSをprobeする。
4. COMPLETEDを永続化する。
5. separate Maintenance Finalizerを起動してWorker/DNSを終了する。
6. Runtime MSIとbundle registrationをuninstallする。

target designのFinalizerは任意command/pathを受け取らず、固定ProductCodeと検証済みmanifestだけを処理します。自身を含むRuntime削除はWorker process内で行いません。このMaintenance Finalizer経路とmanifest署名は初回alphaでは未実装です。

自動uninstall失敗時はblockを再作成せず、inactive `UNINSTALL_PENDING` としてstartup taskが削除だけ再試行します。

## 12. Timeとreboot

保存値:

```text
activated_at_utc
expires_at_utc
requested_duration
boot_id
monotonic_anchor
last_heartbeat_utc
```

- 同一bootではUTCとsuspend-aware monotonic elapsedの両方を通常終了判定に使う。
- timezone変更はUTC deadlineを変えない。
- reboot後はCapsuleのUTC deadlineを使う。
- PCがdeadline中にoffなら、次回startupのExpiry Finalizerが即releaseする。
- 管理者によるsystem clockの意図的変更は保証対象外。

## 13. IPCとstatus

Appはlocal Named PipeでActivation Serviceへ接続します。

```text
GetCapabilities
GetStatus
GetTargetCatalog
PrepareLease
CommitLease
WatchStatus
GetDiagnostics
```

存在させないoperation:

```text
CancelLease
ShortenLease
ExtendLease
RemoveActiveTarget
ChangeActiveDeadline
```

App削除後もLease statusはCapsuleとWorkerの正本に残ります。Appを再installした場合は同じLeaseをread-onlyで再接続し、cancel機能を増やしません。

## 14. Failure behavior

| Failure | Behavior |
|---|---|
| App/CLI crash | Leaseへ影響なし |
| Activation Service crash after handoff | Leaseへ影響なし |
| Worker crash/kill | persistent rules維持、Task Scheduler restart |
| DNS Filter crash | 一般DNSも一時失敗、Worker/taskがrestart |
| WFP/BFE restart | persistent filtersを再読込 |
| expiry task missed | startup/periodic taskがdeadlineを検出してrelease |
| release一部失敗 | RELEASE_PENDINGでretry |
| App package deleted | status UIなし、Lease継続 |
| Runtime package/tasks manually destroyed | 保証外 |

## 15. Technologyとrepository

- UI: .NET 10 LTS、C#、WPF、MVVM
- Activation Service/Worker/DNS/Finalizer: .NET Worker/console host + Windows integration
- State: SQLite + immutable manifest/hash
- Enforcement: user-mode WFP、browser machine policy、adapter DNS
- Scheduling: Windows Task Scheduler
- Installer: WiX Burn + App MSI + Runtime MSI

```text
src/
  DistractionFirewall.Core/
  DistractionFirewall.Contracts/
  DistractionFirewall.App/
  DistractionFirewall.Cli/
  DistractionFirewall.ActivationService/
  DistractionFirewall.LeaseWorker/
  DistractionFirewall.DnsFilter/
  DistractionFirewall.Finalizer/
  DistractionFirewall.Enforcement.Windows/
config/targets/youtube.json
installer/
  App/
  Runtime/
  Bundle/
tests/
  Unit/
  Contract/
  LeaseLifecycle/
  Integration.Windows/
  BrowserE2E/
  InstallerE2E/
  UI/
```

## 16. Phase 1 validation gates

- Lease handoff後にApp、App MSI、App root、Activation Serviceを個別に削除してもYouTube blockが継続する。
- WorkerがAppのchild/job/login sessionに属していない。
- Worker kill後、persistent WFP/browser rulesが残り、periodic taskがWorkerを再起動する。
- normal reboot後にstartup taskが同じLeaseをresumeする。
- expiry task単独でもrules/DNS/policiesをreleaseできる。
- Active bundle uninstallがAppだけを削除し、Runtimeを残す。
- deadline後にdeferred Runtime uninstallが完了する。
- finalizer failure後、blockを復活させずuninstallだけ再試行する。
- general Web/Google collateral、DNS restore、YouTube browser/media coverageが既存gateを満たす。
- Runtime/task/WFPを特定して破壊する管理者が解除できることと、非保証文言が一致する。
