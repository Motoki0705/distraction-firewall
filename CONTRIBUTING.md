# コントリビューションガイド

Distraction Firewallへの貢献を歓迎します。特権処理と期限前解除不能という性質上、通常のデスクトップアプリよりも小さく、検証可能な変更を優先します。

## 開発環境

- Windows 11 x64
- .NET SDK 10.0.302
- PowerShell 7を推奨
- Git

リポジトリルートから次を実行してください。

```powershell
pwsh -NoProfile -File ./eng/restore.ps1
pwsh -NoProfile -File ./eng/build.ps1 -Configuration Release
pwsh -NoProfile -File ./eng/test.ps1 -Configuration Release
```

依存関係を意図的に更新する場合だけ、ロックファイルを更新するrestoreを実行します。

```powershell
pwsh -NoProfile -File ./eng/restore.ps1 -UpdateLockFiles
```

更新されたロックファイルを確認し、依存関係の変更理由をPull Requestに記載してください。

## 変更の進め方

1. 目的が1つの短いブランチを作成します。
2. 実装と同じPull Requestでテストを追加します。
3. 上記のrestore、build、testを実行します。
4. 仕様、セキュリティ境界、アーキテクチャを変える場合は`docs/`またはADRを更新します。
5. Pull Requestテンプレートを埋め、CIの`CI / gate`とDependency Reviewが成功することを確認します。

## 実装上の原則

- UIやCLIからWFP、DNS、machine policyを直接変更しないでください。
- Active Leaseを解除、短縮、延長、対象変更するAPIを追加しないでください。
- 時刻、ファイルシステム、ネットワーク、OS操作は抽象化し、単体テスト可能にしてください。
- 特権側はUIやCLIからの入力を信頼せず、認証、認可、範囲、整合性を再検証してください。
- App packageとLease Runtimeのライフサイクルを混在させないでください。
- ログには完全なDNS履歴、トークン、秘密情報、不要な端末固有情報を残さないでください。

## テスト

テストプロジェクトは`tests/`配下に置きます。CIはすべての`tests/**/*.csproj`を検出し、それぞれのTRXをartifactとして保存します。

最低限、変更に応じて次を確認してください。

- 期限、状態遷移、不変条件の単体テスト
- IPC DTOとバージョン互換性の契約テスト
- Core、UI、特権実装の参照方向を守るアーキテクチャテスト
- OS変更を行わないfake backend統合テスト

実WFP、adapter DNS、ブラウザポリシー、再起動を扱うテストは、通常のPull Request CIで実行しません。使い捨ての隔離Windows環境で行ってください。

## セキュリティ問題

脆弱性の可能性がある内容はPull Requestや公開Issueへ投稿せず、[SECURITY.md](SECURITY.md)に従って非公開で報告してください。
