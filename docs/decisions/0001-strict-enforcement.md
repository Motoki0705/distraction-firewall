# ADR-0001: WFP strict egressとNetwork Broker案

- Status: Rejected
- Proposed: 2026-08-15
- Rejected: 2026-08-15
- Superseded by: [ADR-0002](0002-layered-youtube-enforcement.md)

## Former decision

当初は、日常利用者を標準ユーザーに限定し、管理者資格情報とdisk recovery keyを本人から分離した上で、Network Broker以外の全outbound trafficをWFPで拒否する案を検討しました。

この方式はDoH、portable browser、user-space VPN等への耐性を高めますが、proxy非対応アプリ、ゲーム、同期、独自protocolまで通信不能にし、installer/recovery/driver検証も複雑になります。

## Reason for rejection

要件が次のように変更されました。

- local administratorによる解除防止は不要。
- 製品UI/APIに解除機能を置かないことで十分な摩擦を作る。
- Version 1はYouTubeだけをblockする。
- cloud browser、relay、保存済みcontent等はscope外。
- 将来targetを追加できる設計余地だけを残す。

この要件では全outboundをBrokerへ強制する副作用が利益を上回ります。現在の決定はbrowser policy、local DNS Filter、target-IP WFPを組み合わせる[ADR-0002](0002-layered-youtube-enforcement.md)です。

## Historical value

将来、managed device、parental control、admin credential分離、強いVPN/VM耐性が再び要件になった場合は、この案を新ADRで再評価できます。Version 1へ暗黙に戻してはいけません。
