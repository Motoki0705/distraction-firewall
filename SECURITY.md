# セキュリティポリシー

Distraction Firewallは、Windowsの特権サービス、ネットワーク制御、永続ルールを扱います。脆弱性と思われる情報は公開Issueに詳細を書かず、非公開で報告してください。

## サポート対象

正式リリース前は、`main`の最新状態だけをセキュリティ修正対象とします。署名済みの安定版を公開した後は、この表をリリース方針に合わせて更新します。

| バージョン | サポート |
|---|---|
| `main` / 開発版 | 対象 |
| 過去の開発スナップショット | 対象外 |

## 脆弱性の報告

1. GitHubのSecurityタブから、Private Vulnerability ReportingまたはPrivate Security Advisoryを利用してください。
2. 非公開報告が利用できない場合は、悪用手順や機密情報を含めず、保守者へ非公開連絡手段を確認するIssueを作成してください。
3. 影響を受けるバージョン、再現条件、期待する動作、実際の動作を記載してください。
4. ログを添付する前に、ユーザー名、パス、IPアドレス、DNS履歴、トークンを除去してください。

特に次の報告を重視します。

- Active Leaseを期限前に解除、短縮、変更できる
- 標準ユーザーが特権サービス、Lease状態、WFP、DNS、ブラウザポリシーを変更できる
- Named PipeやローカルIPCの認証・認可を回避できる
- サービス、インストーラー、更新経路から権限昇格できる
- 正常な期限到達後も一般通信またはDNSが復旧しない
- 機密情報がログ、クラッシュダンプ、CI artifactへ保存される

受領後は、影響と再現性を確認し、修正と公開方法を報告者と調整します。現時点でバグ報奨金制度はありません。

## セキュリティ境界

本プロジェクトは、日常利用者が標準ユーザーであり、管理者資格情報を自由に使用できない運用を前提にします。管理者がLease Runtime、Task Scheduler、WFPオブジェクトなどを個別に破壊する操作、Safe Mode、別OS、外部VPNやVMによる回避は保証対象外です。詳細は[脅威モデル](docs/03-security-threat-model.md)を参照してください。

## リポジトリ管理者向け設定

このリポジトリではCodeQLの独自workflowをコミットせず、GitHubのDefault setupを使用します。管理者はSettingsのCode securityからC#のDefault setup、Dependabot alerts、Dependabot security updates、Secret scanning、Push protectionを有効にしてください。
