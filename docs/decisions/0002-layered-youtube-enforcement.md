# ADR-0002: YouTube向け階層型ブロックを採用する

- Status: Accepted
- Date: 2026-08-15
- Related: [Product requirements](../01-product-requirements.md)、[Architecture](../02-system-architecture.md)、[Guarantee boundary](../03-security-threat-model.md)、[ADR-0003](0003-independent-lease-runtime.md)
- Supersedes: [ADR-0001](0001-strict-enforcement.md)

## Context

Version 1ではWindows 11端末全体の通常経路からYouTubeを一定時間blockします。開始後の製品UI/APIには解除・短縮・延長を作りません。一方、local administratorがRuntime、WFP、DNS、browser policyを特定して行うOS-level解除、cloud browser、relay、保存済みcontentへの対抗は不要です。App削除はこの非保証へ含めません。

HTTPSではTLS確立後のpath/query/headerが暗号化されるため、packetをwatchして完全URLを常に読むことはできません。[RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html) YouTubeはweb UI、short URL、API、embed、media CDN、static assetに複数domainを使うため、一つの`www.youtube.com` ruleでも不十分です。

## Decision

次の三層を組み合わせます。

1. Chrome/Edge/Firefox machine URL policy
   - 通常browser navigationをhost/URL patternで拒否する。
   - 対応browserのDoHをOS DNS経路へ戻す。
2. Local DNS Filter
   - adapter DNSをloopback serviceへ向ける。
   - target exact/suffix/CNAMEを拒否する。
   - allowed queryを開始前resolverへ転送する。
3. user-mode WFP target-IP filter
   - target hostのpre-resolutionとDNS observationから得たIPをblockする。
   - IPv4/IPv6、TCP/UDPと開始済みmedia flowを扱う。
   - 全outboundをblockせず、risk評価済みtarget IPだけをblockする。

Activation Serviceが三層を適用して独立したLease Workerへownershipをhandoffし、Workerがdeadline後に自動復元します。UIは非昇格で、Named Pipeから開始・状態照会だけを行います。App削除との独立性はADR-0003で定めます。

## Target design

CoreとIPCは複数の `TargetDefinition` collectionを扱います。Version 1のcatalogはYouTube一件だけです。

```text
TargetDefinition
  stable_id
  exact_hosts[]
  suffix_hosts[]
  cname_suffixes[]
  browser_url_patterns[]
  ip_block_policy
  collateral_impact
```

YouTube固有domainはJSON catalogとtest fixtureへ置き、Coreのconditionに埋め込みません。将来のsite追加はdefinition、test、UI resourceを追加する方式にします。

## Session design

- 1分以上12時間以下、または12時間以内の指定時刻まで。
- 同時Active sessionは一件。
- target/start/deadline/rule snapshotはActive後immutable。
- UI、CLI、Named Pipe、notification、通常uninstallerにcancel/shorten/extendを作らない。
- UI/App削除、logoff、sleep、hibernate、通常reboot、Activation Service restart後も継続する。
- 管理者がLease Worker/Runtime/WFP/DNS/registryを特定して行う直接操作は防止しない。

## Considered alternatives

### Hosts file only

不採用です。wildcardを扱えず、subdomain/CDN変化、cache、DoH、既存connectionに弱いためです。

### Browser policy only

一層として採用しますが、browser外、PWA/WebView差、既存media flowを補えないため単独採用しません。

### DNS Filter only

一層として採用しますが、DNS cache、独自name resolution、開始済みconnectionを補えないため単独採用しません。

### WFP target-IP only

一層として採用しますが、dynamic CDNとshared IPによる漏れ・誤遮断があるためdomain-awareなbrowser/DNS layerを併用します。

### Strict egress + HTTP Network Broker

不採用です。domain判定精度と回避耐性は高いものの、全アプリのtrafficをproxyへ強制し、YouTube以外のnetwork互換性を大きく損ないます。現在の管理者耐性不要という要件には過剰です。

### TLS MITM proxy

不採用です。独自root CA、certificate pinning、QUIC互換性、privacy/security負担に対し、YouTube全体をblockする要件ではpath復号の利益がありません。

### Windows Firewall FQDN rule only

比較用backendにはできますが主方式にしません。Microsoftはdynamic keywordについてsecure DNS、proxy、VPN、DNS cache等の制約を説明しています。[Windows Firewall dynamic keywords](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/dynamic-keywords)

## Consequences

### Positive

- 通常のChrome/Edge/FirefoxとOS DNSをdomain単位でblockできる。
- WFPが既存media connectionとcache済みIPを補う。
- YouTube以外の全network trafficをproxyへ強制しない。
- TLS本文を復号せず、閲覧履歴を収集しない。
- 管理者耐性用のboot filter、kernel driver、credential分離が不要。
- generic target contractで将来拡張できる。

### Negative

- 三つのOS integrationと正確なrestore処理が必要になる。
- CDN IP共有によるcollateralを継続testする必要がある。
- custom DoH/VPN/VMや管理者によるRuntime/OS規則の直接操作を防げない。
- DNS Filter failure時に一般DNSが一時停止し得る。
- new YouTube endpointはcatalog updateまで漏れる可能性がある。

## Validation gates

実装をrelease candidateとして承認する前に、使い捨てWindows 11 Home/Pro x64 VMで次を確認します。

- Chrome/Edge/Firefox/PWA/WebView2のYouTube navigationが拒否される。
- YouTube web、short URL、embed、API、media/static hostをfixtureで覆う。
- 開始済みTCP/QUIC media flowが停止する。
- IPv4/IPv6、adapter切替、normal reboot後もdeadlineまで継続する。
- deadline後にbrowser policy、WFP、adapter DNSが元へ戻る。
- 一般Web、download、WebSocket、主要Google機能が不必要に壊れない。
- UI/CLI/Named Pipe/notification/通常uninstallerにearly cancelがない。
- test用の第二target definitionを追加してもCore/IPCを変更せず展開できる。

管理者によるRuntime/task/WFP等の直接解除、VPN/VM、relay、保存済みcontentはvalidation gateに含めず、known limitationとして文書と実挙動を合わせます。App process/package/root削除への継続性はADR-0003の必須gateです。
