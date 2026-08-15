# プロダクト要件

## 1. 目的

利用者がYouTubeを選び、最長12時間のブロックを開始すると、終了時刻までWindows 11端末全体の通常のブラウザ・アプリからYouTubeへアクセスしにくい状態を維持します。

開始時、UIはActivation Serviceへ期限付きLeaseの作成を要求します。作成後の正本と制御は、Appとは別package・別directoryのLease Runtimeへ移ります。製品のUI・CLI・APIには解除、短縮、延長、対象変更の操作を設けません。

> [!IMPORTANT]
> この文書はVersion 1のtarget requirementです。初回alphaはCore、階層enforcement、App/Runtime分離、Active Runtime removalのfail-closed拒否を実装し、非破壊testで検証しています。一方、破壊可能なWindows 11でのDNS/WFP/browser/reboot試験、`REMOVE_AFTER_COMPLETION` の永続化、期限後のRuntime/Bundle自動削除、installed inner PE署名、完全な依存関係SBOM、provenance/SBOM attestationは未実装または未検証です。

## 2. Version 1で保証対象にすること

- UIの通常操作から、Active sessionを終了時刻より前に解除できない。
- CLI、Named Pipe API、通知、tray menuにもcancel/shorten機能を作らない。
- UI終了、App packageの通常アンインストール、App directory削除、Activation Service停止後もLease Workerが継続する。
- サインアウト、スリープ、休止、通常再起動後はTask SchedulerとLease Runtimeが状態を復元する。
- machine scopeの規則により、端末上の全Windowsユーザーへブロックを適用する。
- Chrome、Edge、Firefox、WebView2、YouTube PWAなど、通常のYouTube利用経路を対象とする。
- 終了時刻へ達したらLease Workerまたはexpiry taskが製品所有の規則を解除する。
- Lease Workerが一時停止しても、restart taskが再起動して状態と規則を照合する。

## 3. 保証しないこと

本製品はローカル管理者に対する耐タンパー機能を持ちません。次は許容される回避・非対象です。

- 管理者がLease Worker、Lease Runtime package、Scheduled Task、WFP filter、DNS設定、registry policy、状態ファイルを特定して直接変更する。
- 管理者がLease Workerを強制終了してrestart taskも止める、Lease Runtimeを手動削除する、Safe Mode、別OS、OS再インストール等を使う。
- 独自DoH/VPN/VMなど、通常のOS・ブラウザ経路を意図的に外す。
- cloud browser、remote desktop、任意の中継サイト、別サイトへの再投稿を利用する。
- 既に保存・download・decode済みの動画を見る。

これらへの対抗策は今回のscopeに含めません。ただし、管理者権限を使った操作であっても、UI/App processのkill、App MSIのremove、App rootの削除は保証対象です。保証文言は「Appの削除と開始済みLeaseを連動させず、通常のWindows・ブラウザ経路からYouTubeの公式endpointをブロックする」とします。

## 4. 対象環境

- 初期対応OS: Windows 11 x64
- Windows edition: Homeを含む
- 日常利用account: 標準ユーザー・管理者のどちらも許容
- install/repair/uninstall: 管理者昇格が必要
- package: App packageとLease Runtime packageをSetup bundleで導入
- ブロック開始: installerで登録したowner SIDを既定とする
- ブロック効果: 端末上の全ユーザー

Device Encryption、BitLocker、管理者資格情報の別管理は利用条件にしません。Lease Runtime、Task Scheduler、DNS binding、WFP availability、browser policy適用可否だけをhealth check対象にします。

## 5. 対象サービス

### 5.1 Version 1

ユーザーが選択できる対象はYouTubeだけです。UIは一件のtarget cardを表示し、将来複数targetになっても同じlist UIとService contractを使えるようにします。

YouTube targetは、一つのURLではなく次の用途を束ねた規則です。

- Web UIと主要subdomain
- 短縮URL
- privacy-enhanced embed
- YouTube API
- 動画・音声配信CDN
- YouTube固有の画像・静的asset

実際のhost一覧は `config/targets/youtube.json` で版管理し、unit/integration testのfixtureにします。共有Google infrastructureへの誤遮断を避けるため、広すぎるsuffixやIP blockは用途別にriskを明記します。

### 5.2 将来拡張

Core、Activation Service、Lease Worker、UI、enforcementは `TargetDefinition` のcollectionを処理し、YouTube固有のif文を置きません。

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
  collateral_impact
```

Version 1では組込みYouTube定義だけを読み込みます。custom domain入力、利用者作成target、remote catalog updateは実装しません。新targetはreview済み定義とtestをreleaseへ追加する方式で拡張します。

## 6. 時間指定

- 即時開始のみとする。
- 期間指定は1分以上12時間以下とする。
- UIは15分、30分、1時間、2時間、4時間、8時間、12時間のpresetと任意分数を提供する。
- 「指定時刻まで」は現在より後かつ12時間以内だけを許可する。
- 日をまたぐ場合は日付と `明日` を表示する。
- 12時間を超える入力を自動で丸めず、validation errorにする。
- sleep、hibernate、電源OFF中も経過時間に含める。
- Active後は解除、短縮だけでなく延長も禁止し、sessionを完全にimmutableにする。

Lease RuntimeはUTC deadlineを正本として保存します。同一boot中は単調時計も使い、通常の時計同期や時刻補正で不用意に早く終了しないようにします。管理者による意図的なclock tamperingへの耐性は保証しません。

## 7. ユーザーフロー

### 7.1 初回セットアップ

1. 管理者権限でApp package、Lease Runtime package、Activation Service、DNS Filter、WFP provider、Task Scheduler taskをinstallする。
2. block開始を許可するowner SIDを登録する。
3. Activation Service、Lease Runtime、DNS port、WFP、Task Scheduler、対応browserをdiagnoseする。
4. test targetで適用・復元ができることを確認する。

管理者accountやdisk encryptionのposture評価は行いません。

### 7.2 ブロック開始

```text
対象
☑ YouTube

終了条件
○ 期間       [ 1時間 ▼ ]
○ 終了時刻   [ 今日 18:00 ]

予定終了: 2026-08-15 18:00 JST
[確認へ]
```

1. YouTubeを選ぶ。
2. 期間または終了時刻を選ぶ。
3. Activation Serviceがhealth checkとinput validationを行う。
4. 最終確認で対象、端末全体への適用、開始・終了、副作用を表示する。
5. 「開始後はアプリから解除・変更できない」確認checkを入れる。
6. Activation ServiceがLease capsuleを作り、Lease Workerへ所有権を移し、規則を検証してからActiveを返す。

VPN、独自DoH、VM等を検出した場合はcoverage warningを表示できますが、Version 1ではそれらへの耐性を保証せず、必ずしも開始を拒否しません。

`ip_block_policy.mode=dns_observed` かつ `shared_address_action=block` のtargetではWFPを必須層とします。TTL-validな公開target IPをseedまたはobservationから1件も得られなければ、WFP mutation前に失敗し、rollback後に `ActivationFailed` を返します。YouTubeはexact host群と代表 `seed_hosts` の `www.youtube.com` を初期解決しますが、動的な全 `*.googlevideo.com` endpointの網羅を意味しません。

### 7.3 ブロック中

```text
YouTubeをブロック中

終了: 2026-08-15 18:00 JST
残り: 59分
状態: 正常

このセッションはアプリから解除・変更できません。

[診断情報] [アプリを閉じる]
```

- 解除、短縮、延長、対象変更ボタンを置かない。
- countdownは表示専用とし、終了判断はLease Runtimeが行う。
- UIを閉じても継続する。
- Activation Serviceへ接続できなくてもLease stateを「解除済み」と推測しない。
- 通知は開始、終了10分前、解除完了を既定とする。
- Active中にTTL-validな対象IPが0件になった場合はhealthを `Degraded` とし、最後に所有していたWFP filterを観測回復またはdeadlineまで保持する場合がある。このfail-closed動作では、失効IPへのfilterがTTLを越えて残る可能性をshared-CDN collateralとして扱う。

### 7.4 App削除・アンインストール

Session stateとinstall intentを分離します。

> [!IMPORTANT]
> 以下はstable向けtarget designです。初回alphaはActive Runtime removalをfail-closedで拒否し、App/Runtime packageを分離しますが、`REMOVE_AFTER_COMPLETION` のproduction write path、deadline後のRuntime/Bundle自動削除、`UNINSTALL_PENDING` retryは未実装です。Active中のSetup removalはRuntimeを残し、期限後にSetupを再実行して削除を完了します。

```text
SessionState = ACTIVE
InstallIntent = KEEP | REMOVE_AFTER_COMPLETION
```

- App process終了、App directory削除、App MSI削除はLeaseを変更しない。
- Setup bundleからActive中にuninstallすると、App packageを削除し、Runtimeへ `REMOVE_AFTER_COMPLETION` を記録する。
- Lease Runtime package、Lease Worker、DNS Filter、persistent rules、boot/expiry taskは残る。
- Windowsのprogram一覧には、Lease Runtimeまたは削除予約中のbundleがcompletionまで残る。
- deadline到達後、Lease WorkerがDNS/WFP/browser policyを復元し、すべての規則の解除を確認してCompletedにする。
- `REMOVE_AFTER_COMPLETION` の場合、別のMaintenance FinalizerがRuntime MSIとbundle registrationを削除する。
- 自動uninstall失敗時はblockを復活させず、inactiveな `UNINSTALL_PENDING` として次回bootで再試行する。
- 管理者がLease Runtime自体やTask/WFPを手動破壊できることは許容するが、製品UIにshortcutは置かない。
- 期限後のrule残留には管理者権限のrepair commandを提供する。

## 8. 事前検査

開始を拒否する条件:

- Activation Service、Lease Runtime、Task Schedulerまたはenforcement backendが起動できない。
- 状態を永続化できない。
- Active sessionが既にある。
- YouTube target definitionがinvalidである。
- 時間指定が範囲外である。
- 規則の適用・rollback testに失敗する。
- WFP必須targetでTTL-validな公開target IPを1件もseedまたはobserveできない。

warning条件:

- 対応browserが見つからない。
- VPN、custom DNS/DoH、WSL/VM等、coverage外の経路を検出した。
- 既存の組織browser/DNS policyと競合する。
- YouTube関連の共有hostを遮断することで他Google機能へ影響する可能性がある。

## 9. 状態機械

```text
IDLE
  → PREPARED
  → ACTIVATING
  → ACTIVE
  → RELEASING
  → COMPLETED
  → IDLE
```

- `PREPARED → IDLE`: 確認nonceの期限切れ
- `ACTIVATING` crash: journalと実規則を照合し、完了または安全にrollback
- `ACTIVE` crash: restart taskがLease Workerを再起動し、同じdeadlineと規則を復元
- `RELEASING` failure: `RELEASE_PENDING` として自動再試行
- `COMPLETED`: 製品所有規則の解除確認後のみ

同時Active sessionは一件です。開始requestはidempotency keyを持ち、double clickやtimeoutで重複しません。

Install lifecycleはsession stateとは別に管理します。

```text
AppInstallState     = INSTALLED | REMOVED
RuntimeInstallIntent = KEEP | REMOVE_AFTER_COMPLETION
RuntimeInstallState  = INSTALLED | UNINSTALLING | UNINSTALLED
```

`AppInstallState=REMOVED` または `RuntimeInstallIntent=REMOVE_AFTER_COMPLETION` でも、SessionStateはACTIVEのままです。

## 10. UI–Activation Service API

local versioned Named Pipe RPCを使います。

```text
GetCapabilities
GetStatus
GetTargetCatalog
PrepareLease
CommitLease
WatchStatus
GetDiagnostics
```

意図的に存在させないoperation:

```text
CancelLease
ShortenLease
ExtendLease
RemoveActiveTarget
ChangeActiveEndTime
```

UIは対象IDと時間を要求します。Activation Serviceがtarget definitionを展開し、resolved deadlineとrule hashを返し、Lease Workerを起動します。将来targetが増えてもAPI shapeは変更しません。

## 11. 非機能要件

### Securityと安全性

- UIは非昇格、OS変更はActivation ServiceとLease Runtimeだけが行う。
- AppとLease Runtimeは別install rootに置き、App directory削除がRuntime binary/stateへ波及しない。
- Runtime binary/stateはProgram Files/ProgramDataの通常の管理者ACLで保護する。
- Named Pipeはlocal callerのWindows SIDを検証する。
- 他製品のDNS/firewall/browser policyを所有権確認なしに削除しない。
- TLS中間者証明書を導入しない。
- 管理者によるtamperingは防止対象でなく、検出できればdiagnosticsへ表示する。

### Privacy

- 外部telemetryを既定で送らない。
- 閲覧URL、DNS query履歴、page title、通信本文を保存しない。
- session ID、state transition、target ID/version、rule hash、errorだけを記録する。
- DNS Filterのquery logはdebug時も短時間・明示opt-inとする。

### Accessibility

- keyboard-only、UI Automation、high contrast、text scalingへ対応する。
- 色だけでwarning/errorを区別しない。
- 日本語を初期対応し、全文字列をresource化する。
- date/timeはOS localeと12/24時間設定を尊重する。

## 12. Version 1受入基準

- YouTube website、short URL、embed、PWA、主要media CDNがChrome/Edge/Firefoxでブロックされる。
- 開始前から再生中の動画の停止はrelease E2Eで検証する。現実装は観測済みIPへの次のpacket/requestを遮断対象とするが、未観測/shared CDN上の既存TCP/QUIC flowを決定的に即時終了できるとは保証しない。
- 端末の別Windowsユーザーにもmachine scopeの規則が効く。
- UI終了、Activation Service停止、App MSIの通常削除、App directory削除、logoff、sleep/hibernate、通常reboot後もdeadlineまで継続する。
- UI、CLI、Named Pipe、notification、Setup bundleにearly cancel経路がない。
- Active中のuninstall requestがAppだけを削除し、Lease Runtimeをcompletionまで残す。
- 正常時はdeadline後10秒以内、reboot中に満了した場合はLease Runtime起動後30秒以内を目標に解除する。
- 無関係な一般Web閲覧、DNS、download、WebSocketへの影響が許容範囲内である。
- 管理者によるRuntime/task/WFP等の直接解除、VPN/relay/保存済み動画を防げないというdocumentと実挙動が一致する。
- clean Windows 11 Home/Pro x64 VMでinstall、upgrade、repair、inactive uninstall、deferred Active uninstallが成功する。
