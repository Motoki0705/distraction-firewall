# 1 回の UAC で行う Windows 11 実機検証キャンペーン

## 1. 決定

Distraction Firewall の候補版について、Windows 11 実機で次を 1 回の UAC 同意にまとめて検証する。

1. 必要な場合だけ、既知の旧 Runtime MSI を完全一致マニフェストで回復してアンインストールする。
2. CI が一度だけビルドした候補をインストールする。
3. サービス、失敗時再起動設定、所有する OS オブジェクトを検査する。
4. 元の非昇格プロセスから CLI と UI を検査する。
5. 候補をアンインストールする。
6. 製品残留物と事前取得した端末設定の差分がないことを検査する。
7. 入力、ログ、結果、ハッシュ一覧を証跡として残す。

このキャンペーンはブロック期間を開始しない。`Prepare`、`Commit`、lease start、および UI の開始操作は禁止する。実際の YouTube ブロック機能とは別の、インストーラー候補を安全に受け入れるための検証系である。

## 2. なぜ UAC が 1 回になるか

準備と利用者境界の検査は、すべて非昇格で先に行う。実行時は、非昇格の親プロセスを起動したまま、固定された昇格子プロセスだけを 1 回起動する。

```text
GitHub Actions の build-once candidate
             |
             v
  非昇格: download / provenance / hash / MSI identity 検証
             |
             v
  候補固有 campaign を生成（path / hash / ID / nonce を埋め込み）
             |
             v
  非昇格 parent ------------------------------+
       |                                      |
       | UAC 1 回                             | CLI / UI smoke
       v                                      |（標準 token）
  昇格 child                                  |
  recovery -> install -> service check -------+
       ^                                      |
       +----------- phase JSON ---------------+
       |
       v
  uninstall -> residual / baseline check -> evidence
```

UAC 後にユーザー書き込み可能な `.ps1` を `-File` で読み直す方式は採用しない。親は短い固定 bootstrap を `-EncodedCommand` で渡す。bootstrap は昇格後に次を行う。

- 生成時に固定した子スクリプトの絶対パスと SHA-256 だけを受け持つ。
- 子ファイルを `FileShare.None` で開く。
- 開いた同じ stream のバイト列をハッシュする。
- 一致した同じバイト列だけを UTF-8 としてメモリ実行する。
- 外部引数、任意コマンド、任意パスを受け取らない。

これにより、UAC ダイアログを待っている間の「検査後、ロード前」の差し替えを防ぐ。昇格子はさらに、候補マニフェスト、外部 provenance envelope、raw artifact ZIP、各バイナリ、回復 MSI を再検証する。

## 3. アカウント境界

キャンペーンの親と子は同じ SID でなければならない。別管理者の資格情報を入力する over-the-shoulder elevation は拒否する。

そのため、この実機検証を行うときだけ、専用のローカル管理者アカウントへサインインし、そのアカウントの通常の filtered token から親を開始する。日常利用の標準ユーザーから別管理者の資格情報を入力して実行する用途ではない。これは製品の通常利用アカウントを標準ユーザーにする設計と矛盾せず、リリース候補検証の操作者を分離する境界である。

## 4. build-once 候補の信頼境界

### 4.1 payload manifest

候補内の `distraction-firewall/build-once-candidate/v1` は、次を固定する。

- repository、commit SHA、`refs/heads/main`
- `.github/workflows/release-candidate.yml`
- workflow run ID / attempt
- setup、App MSI、Runtime MSI、checksum、SPDX inventory のファイル名、サイズ、SHA-256
- MSI ProductCode、PackageCode、UpgradeCode、ProductVersion
- Bundle provider key、Bundle UpgradeCode、detached Burn engine のサイズと SHA-256
- Authenticode 状態と signing disclosure

artifact ID と artifact ZIP digest はアップロード前には自己包含できないため、payload manifest では必ず `null` とする。

### 4.2 external provenance envelope

アップロード後の GitHub API 情報は `distraction-firewall/live-validation-provenance/v1` に保存する。これは artifact ID、artifact 名、raw ZIP の digest / size、workflow run、候補マニフェスト hash を結ぶ。

取得時は Windows PowerShell 5.1 の native stdout リダイレクトを使用しない。`Get-BuildOnceCandidate.ps1` は `HttpClient` の byte stream をファイルへ直接保存し、GitHub API の `sha256:` digest とサイズに一致することを確認する。GitHub token は API の最初の request にだけ付与し、signed blob URL には別の匿名 client を使う。

GitHub CLI は PATH 解決しない。native Program Files 直下の `GitHub CLI\gh.exe` だけを使用し、Program Files、`GitHub CLI` directory、leaf の owner / ACL / non-reparse、Authenticode `Valid`、GitHub, Inc. publisher を検証する。実行時は `GH_HOST=github.com` と明示的な hostname を使い、Enterprise/config redirect 用の process environment override を除外する。CLI の exact path、hash、version、signer は receipt、campaign lock、最終 evidence に残す。

### 4.3 exact archive

raw ZIP と展開先は、次の 9 ファイルだけを許可する。

1. setup EXE
2. App MSI
3. Runtime MSI
4. checksum inventory
5. SPDX distribution inventory
6. candidate manifest
7. hosted validation evidence
8. candidate subject checksums
9. GitHub provenance bundle

ZIP は flat でなければならず、directory entry、重複名、余分なファイルを拒否する。展開後の全ファイルを raw ZIP entry と比較する。7 つの attestation subject は、固定 repository、固定 workflow、source SHA、`refs/heads/main`、hosted runner 制約で `gh attestation verify` する。

## 5. 非昇格での準備

Windows PowerShell 5.1 を、専用管理者アカウントの非昇格ウィンドウで使う。以下の操作は UAC を表示せず、MSI やサービスを変更しない。

### 5.1 GitHub artifact の取得

```powershell
$workspaceRoot = '<workspace-root>'
$repo = Join-Path $workspaceRoot 'repo'
$download = Join-Path $workspaceRoot 'candidate-download-123456'
$windowsPowerShell = [IO.Path]::Combine(
  [Environment]::GetFolderPath([Environment+SpecialFolder]::System),
  'WindowsPowerShell', 'v1.0', 'powershell.exe')

& $windowsPowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File "$repo\eng\live-validation\Get-BuildOnceCandidate.ps1" `
  -ArtifactId '123456' `
  -OutputDirectory $download
```

出力は次の通りである。

- `github-artifact-123456.zip`: API digest と一致する raw bytes
- `candidate\`: safe flat extraction
- `provenance-envelope.json`: campaign generator 用 envelope
- `github-api-receipt.json`: 取得時 API 応答から絞り込んだ証跡

同名の出力ディレクトリは上書きしない。

### 5.2 候補固有 campaign の生成

```powershell
$manifests = @(Get-ChildItem "$download\candidate\*.candidate-manifest.json" -File)
if ($manifests.Count -ne 1) { throw 'Expected exactly one candidate manifest.' }
$manifest = $manifests[0]
$campaign = Join-Path $workspaceRoot 'campaign-123456'

& $windowsPowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File "$repo\eng\live-validation\New-LiveValidationCampaign.ps1" `
  -CandidateManifestPath $manifest.FullName `
  -ProvenanceEnvelopePath "$download\provenance-envelope.json" `
  -PackageDirectory "$download\candidate" `
  -CandidateArchivePath "$download\github-artifact-123456.zip" `
  -OutputDirectory $campaign
```

既知の旧 Runtime partial state が存在する端末では、レビュー済みの回復マニフェストと回復 MSI directory を追加する。

```powershell
$reviewRoot = '<review-root>'
& $windowsPowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File "$repo\eng\live-validation\New-LiveValidationCampaign.ps1" `
  -CandidateManifestPath $manifest.FullName `
  -ProvenanceEnvelopePath "$download\provenance-envelope.json" `
  -PackageDirectory "$download\candidate" `
  -CandidateArchivePath "$download\github-artifact-123456.zip" `
  -RecoveryManifestPath (Join-Path $reviewRoot 'runtime-recovery-manifest.json') `
  -RecoveryPackageDirectory (Join-Path $reviewRoot 'package') `
  -OutputDirectory $campaign
```

generator は GitHub API をもう一度照合し、MSI を read-only で開いて identity を確認し、9 ファイルと attestation を検証してから、候補固有の親・子・lock を生成する。生成済み campaign は上書きも再利用もしない。すべての例は新しい native x64 Windows PowerShell 5.1 を `-NoProfile` で起動する。呼び出し元 session の profile や global function を campaign の command resolution に持ち込まない。

## 6. 実行手順

### 6.1 読み取り専用 preflight

最初に `-VerifyOnly` を実行する。これは UAC、MSI、サービス、registry の書き込みを行わない。

```powershell
& $windowsPowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File "$campaign\Start-LiveValidationCampaign.ps1" -VerifyOnly
```

次の場合は本実行へ進まない。

- active lease がある。
- CBS / Windows Update / Windows Installer の pending state がある。
- pending computer rename がある。
- 候補、raw ZIP、manifest、envelope、回復 MSI の fingerprint が変わった。
- Windows 11、x64、Windows PowerShell 5.1、同一 SID の条件を満たさない。

`PendingFileRenameOperations` と `PendingFileRenameOperations2` は、value type、pair 順序、空 destination を含めて基準化する。空 source と不完全 pair は拒否する。

### 6.2 1 回の UAC を伴う本実行

```powershell
& $windowsPowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File "$campaign\Start-LiveValidationCampaign.ps1"
```

このコマンドで表示される UAC は 1 回だけである。親の唯一の UAC call は module-qualified `Microsoft.PowerShell.Management\Start-Process` であり、session 内の同名 function を解決しない。downloader、generator、親、昇格 child は、最初の非 core command より前に native `$PSHOME\Modules` だけへ `PSModulePath` を固定し、system module manifest を絶対 path で import して autoload を無効化する。UAC 対象の `powershell.exe` と child が使う `msiexec.exe` / `netsh.exe` は environment の `SystemRoot` から解決せず、Windows known folder から導出して non-reparse、privileged owner/ACL、Microsoft Windows Authenticode signer を検査する。

親は既知の managed-runtime loader 変数を Process / User / Machine scope で値を記録せず検査する。RunAs の直前にも再検査し、呼び出し中だけ危険変数を消去して `PATH`、`PSModulePath`、`PATHEXT`、`PSExecutionPolicyPreference`、Windows directory を固定し、成功・キャンセル・例外のいずれでも元の process environment を `finally` で復元する。clean snapshot は `execution-environment.json` に残す。キャンセルした場合、またはいずれかの検証が失敗した場合は fail closed とし、候補を合格扱いにしない。

## 7. 固定 phase protocol

| phase | token | 内容 |
|---|---|---|
| parent preflight | 標準 | source hash、reboot、PFR、DNS、browser policy の基準化 |
| recovery | 昇格 | 許可された旧 Runtime ProductCode だけを recache / exact uninstall |
| candidate install | 昇格 | protected stage の hash 済み setup を固定引数で実行 |
| service acceptance | 昇格 | SCM command、LocalSystem、Own Process、PID、実 image path、failure actions、seed を検査 |
| awaiting smoke | 昇格 | nonce 付き phase JSON を書き、親を待つ |
| CLI smoke | 標準 | `targets --json`、`status --json`、`diagnose --json` のみ |
| UI smoke | 標準 | UI Automation の読み取りと duration ComboBox の展開だけ |
| uninstall | 昇格 | exact Burn uninstall。必要時のみ候補 ProductCode の MSI fallback |
| residual gate | 昇格 | product / bundle / service / cache / task / WFP / path / baseline を検査 |

phase JSON は campaign ID、32-byte nonce、owner SID、elevation 状態を含む。子は、標準ユーザー smoke が `lease_start_invoked=false` であることを確認する。

## 8. CLI / UI の受け入れ条件

CLI は固定した 3 コマンドだけを直接起動し、次を確認する。

- target が YouTube 1 件だけである。
- status が idle で lease ID がない。
- diagnostics の全 check が healthy である。
- smoke 前後に `active-lease.json` がない。

UI は開始ボタンを invoke しない。日本語 UI から少なくとも次を確認する。

- `YouTube`
- `期間を指定`
- `指定時刻まで`
- `任意の分数`
- `確認へ`
- `15分`、`30分`、`1時間`、`2時間`、`4時間`、`8時間`、`12時間`

ComboBox は選択せず、候補一覧を読むための Expand / Collapse だけを行う。

## 9. 回復とアンインストール

回復は `distraction-firewall/runtime-recovery/v1` のうち、incident `pretag-alpha2-runtime-uninstall-1603` 専用の exact manifest だけで有効になる。manifest SHA-256 `29962be5b7992ac17b13ac4aaa0c46320c5a5b4fba481e3b1e46a36bad9366e2` と、回復 MSI SHA-256 `ef35d8ccb1a110f70dd4f6a9989bbc2b30a0b2b467b4fdc380ce6973b83c50da` を schema、generator、昇格 child の三層で固定する。自己申告の `approvedForMachineRecovery` だけでは新しい MSI を許可しない。将来の incident は code review を伴う allowlist 更新が必要である。`Win32_Product`、DisplayName 検索、UpgradeCode family 全削除、wildcard directory 削除は使わない。

回復処理は次を要求する。

- Runtime ProductCode、旧 PackageCode、回復 PackageCode、ProductVersion が一致する。
- mutation 前の Runtime ProductState が `INSTALLSTATE_DEFAULT (5)` で、Windows Installer の登録済み `VersionString` が code-approved `expectedInstalled.productVersion` と完全一致する。Advertised / Absent / Unknown / Broken と version mismatch は拒否する。
- Windows Installer `LocalPackage` が `C:\Windows\Installer` 直下で、size / SHA-256 / PackageCode が一致する。
- 既存 activation service が固定 quoted path、LocalSystem、Auto / Running、own-process、実 process image、delayed auto-start、3 回の 5 秒 restart failure action、owner SID / ProductInstanceId / DataRoot seed と一致する。service executable は protected Program Files chain 内の non-reparse / privileged ACL で、incident 固定 size `162816`、SHA-256 `28ceaabde4f29903813e1431f6599c5072385f7162b7309fa2bb97ea9f67626b`、Authenticode `NotSigned` と一致する。
- 最初の `msiexec` より前に、旧 Bundle registration / dependency / cache が absent、旧 App ProductCode が direct state `-1` かつ UpgradeCode family から absent、列挙した package dependency が absent、orphan Package Cache が absent または exact layout / hash / MSI identity / owner / ACL であることを一括検査する。固定 Task Scheduler folder と WFP provider / sublayer / filter reference も absent を要求する。
- 回復 MSI を管理者のみの protected stage へコピー後、再検証する。
- exact ProductCode を recache 後、exact ProductCode をアンインストールする。
- `C:\ProgramData\DistractionFirewall\Runtime\v1\cleanup-failure.json` があれば、schema v1 と固定 field set を検査して証跡へ退避する。

既知の orphan Package Cache は、manifest に列挙した direct child だけを対象とする。product / dependency / bundle registration が存在しないこと、単一 MSI layout、MSI identity、hash、owner、ACL、non-reparse を確認する。owner は SYSTEM / Administrators / TrustedInstaller に限定し、全 allow ACE を走査して、それ以外の SID に write / delete / ACL / owner 変更権があれば拒否する。mandatory integrity label は、通常の `Get-Acl` SACL 取得に依存せず、非昇格でも利用できる Windows の `LABEL_SECURITY_INFORMATION` だけを読み取る。明示 label がない場合は Windows の effective Medium として受理し、明示 Medium / High / System だけを許可する。Untrusted / Low、不明な level / policy、複数・矛盾・parse failure は fail closed に拒否する。Package Cache root 自体も同じ条件で検査し、削除直前にもう一度 fingerprint を確認して protected stage へ移動してから削除する。条件を満たさない残留物は削除せず、campaign を失敗させる。

候補 install も、Burn の最初の呼び出し前に App / Runtime の exact ProductCode が direct state `-1` であることを要求する。UpgradeCode 列挙から漏れる broken / advertised registration を fresh install として扱わない。`CommonApplicationData\Package Cache` root は既存の directory でなければならず、non-reparse、privileged owner/ACL を検査する。root が missing / file / junction / weak ACL の場合、この campaign は安全な作成や修復を試みず fail closed に停止する。

## 10. 最終 residual gate

合格には、少なくとも次がすべて成立しなければならない。

- 候補 App / Runtime ProductCode が absent
- 固定 App / Runtime UpgradeCode family が空
- Bundle registration と dependency providers が absent
- Windows Installer LocalPackage が absent
- 候補固有 Package Cache directories が absent
- activation service、Program Files roots、Runtime DataRoot、installer seed、active marker が absent
- common Start Menu folder が absent
- `\DistractionFirewall` Task Scheduler folder が absent
- 固定 WFP provider、sublayer、filter reference が 0
- DNS server addresses と Chrome / Edge / Firefox machine policy が preflight と完全一致
- PFR baseline が順序も含めて維持される

Burn が自身の engine を遅延削除する場合だけ、owner Temp 直下の `DELxxxx.tmp`、空 destination、manifest の detached engine size / SHA-256 と一致する追加 PFR pair を許可する。広いパターンや既存アプリ由来という推測では許可しない。

WFP の machine-wide raw XML は protected scratch にだけ一時作成し、`finally` で削除する。利用者が読める evidence へコピーするのは owned object の有無、件数、inventory hash だけである。raw XML の削除に失敗した場合は campaign 自体を失敗させる。

## 11. 証跡

`campaign\evidence` は次を含む。

- exact candidate manifest
- external provenance envelope
- hosted evidence、subject checksums、provenance bundle
- 使用時は exact recovery manifest
- loader environment の scope-only clean snapshot（変数値は含めない）
- 標準ユーザー CLI stdout / stderr と UI smoke JSON
- Burn / MSI install、recache、uninstall logs
- 使用時は検証済み cleanup failure diagnostic
- source SHA、workflow run / attempt、artifact ID / digest、ProductCode、service 実 PID / path / executable hash を含む `campaign-result.json`
- 全 evidence file の `evidence.sha256`

protected stage の teardown が失敗した場合も合格にしない。エラーを `protected_stage_teardown_error` と `cleanup_errors` に記録する。

## 12. CI / CD との関係

CI は `tests/LiveValidation/DistractionFirewall.LiveValidation.Tests.csproj` を通常の solution build / test に含める。この test project は次を自動化する。

- JSON Schema metaschema と canonical fixture
- strict SemVer の正例 / 反例
- Windows PowerShell 5.1 AST parse
- 埋め込み native inspection C# の compile-only 検査
- UAC bootstrap の hash / same-byte / command length 境界
- fixed CLI/UI allowlist と lease 非開始
- raw ZIP / GitHub API / attestation binding
- recovery orphan cache の exact ACL / double fingerprint
- reboot / PFR / DNS / browser baseline
- service / Package Cache / Task / WFP residual gate
- WFP raw XML の例外経路での削除

CI では UAC、MSI install / uninstall、service、WFP、registry の変更を実行しない。実機 campaign は candidate artifact を対象に手動で行う CD promotion gate であり、合格 evidence のレビュー後に同じ artifact ID / digest の候補だけを Release へ昇格する。再ビルドした別バイト列への差し替えは禁止する。

## 13. サブエージェント分担

持続的な開発では、変更領域を分離して並行作業する。

| 担当 | 所有境界 | 主な確認 |
|---|---|---|
| candidate / promotion | candidate workflow、seal、promotion | build-once、canonical manifest、artifact provenance、release asset hash |
| product cleanup / recovery | Runtime cleanup、diagnostic、recovery MSI | uninstall failure 原因、secret-free diagnostic、exact recovery identity |
| live-validation campaign | `eng/live-validation`、専用 tests、本書 | one-UAC protocol、TOCTOU、standard-token smoke、residual evidence |
| integrator / reviewer | 全体 read-only review | 境界間 schema、固定 ID、CI 総合結果、実機実行可否 |

同じファイルを複数担当が編集しない。canonical manifest と recovery manifest は fixture / schema test を共有し、統合担当が最後に solution build、全 test、workflow lint、PowerShell AST を再実行する。

## 14. 制限

- 本 campaign 自体は YouTube lease を開始しないため、ブロックの実効性試験は別の承認済み試験計画で行う。
- クラウドブラウザ、任意中継サイト、保存済み動画は製品 MVP と同様に対象外である。
- active lease 中の upgrade / uninstall は試みない。
- preflight 後に端末の DNS、browser policy、PFR が第三者により変更された場合、誤差として許可せず失敗する。
- 管理者が意図的に候補固有 child やサービスを kill できることは Windows の権限モデル上防がない。この campaign の目的は、通常の開発者が 1 回の UAC で安全に検証を完了できることと、任意の SYSTEM command broker を作らないことである。
- campaign 開始前から同一ユーザーの標準 token process が侵害されている場合、または `powershell.exe` の CLR 初期化より前に profiler / startup-hook code を読み込ませる永続設定を攻撃者が配置済みの場合は対象外である。parent は既知の `COR_*` / `CORECLR_*` / `COMPLUS_*` / `APPDOMAIN_MANAGER_*` / .NET code-loader 変数を Process / User / Machine scope で fail closed に検査し、RunAs の間だけ process environment を固定して復元するが、これは native pre-CLR security boundary ではない。この脅威を対象に広げる場合は、署名済み native launcher が必要になる。
- 将来追加される未知の runtime loader 環境変数と、preflight 後に同一ユーザーが parent process を能動的に改変する競合は対象外である。
