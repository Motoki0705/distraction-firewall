# 設計ドキュメント

このディレクトリはDistraction Firewallの要件、アーキテクチャ、保証範囲、CI/CD、開発計画の正本です。

## 現在のプロダクト方針

- Version 1で制限する対象はYouTubeだけとする。
- 将来別サイトを追加できるtarget catalogとcontractを用意する。
- アプリ内にはActive sessionの解除・短縮・延長機能を作らない。
- StartLease後はAppから独立したLease Runtimeへ制御を移す。
- UI終了、App package/directory削除、Activation Service停止、通常再起動後も自動継続する。
- 管理者がLease Worker/Runtime/task/WFP/DNS/browser policyを特定して直接破壊する操作には対抗しない。
- cloud browser、中継サイト、remote desktop、保存済み動画はscope外とする。
- 通常の他サイト通信を維持するため、全通信をlocal proxyへ強制しない。

## 読む順序

1. [プロダクト要件](01-product-requirements.md)
2. [システムアーキテクチャ](02-system-architecture.md)
3. [脅威モデルと保証範囲](03-security-threat-model.md)
4. [CI/CD・配布設計](04-ci-cd-release.md)
5. [2フェーズ開発計画](05-development-plan.md)
6. [サブエージェント協働計画](06-agent-collaboration.md)
7. [ADR-0002: YouTube階層型ブロック](decisions/0002-layered-youtube-enforcement.md)
8. [ADR-0003: App非依存のLease Runtime](decisions/0003-independent-lease-runtime.md)

[ADR-0001](decisions/0001-strict-enforcement.md)は、以前の「標準ユーザー + WFP strict egress + Network Broker」案です。要件変更によりRejectedとし、意思決定履歴として残します。

## 設計判断の優先順位

1. 製品内に簡単なearly cancel経路を作らないこと
2. Appの削除とActive Leaseの寿命を連動させないこと
3. 通常のWindows・browser利用でYouTubeを端末全体から止めること
4. deadline後に確実に自動復元すること
5. 他サイトや他アプリの通信を不必要に止めないこと
6. 将来のtarget追加時にCoreを作り直さないこと

## 用語

- **Target**: YouTubeなど、複数domainとenforcement ruleを束ねた定義
- **Session**: target、開始、終了、rule snapshotを固定した一回のblock
- **Lease**: Appの寿命から独立し、deadlineまでSessionとenforcement artifactを所有する期限付きRuntime契約
- **Activation Service**: UIのStartLease requestを検証し、Lease Runtimeを作成・起動するWindows Service
- **Lease Worker**: Appとは別package/directoryで、deadlineまでsessionとOS規則を管理するbackground process
- **DNS Filter**: Lease Runtime内で対象domainを拒否し、それ以外を元のresolverへ転送するlocal process
- **通常解除経路なし**: 製品APIにはcancelがなくApp削除でもLeaseは終わらないが、Runtimeを直接破壊するlocal administratorへの耐性は保証しない状態
