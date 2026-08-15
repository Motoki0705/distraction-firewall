# Windows installer and release contract

The installer toolchain is deliberately pinned to WiX Toolset `5.0.2`
(`WixToolset.Sdk`, Bootstrapper Applications, and Util). WiX 7 OSMF variables
or EULA-acceptance switches are not part of this build.

`eng/package.ps1 -Version <semver>` consumes self-contained `win-x64` publish
outputs and creates these files in `artifacts/package/`:

- `distraction-firewall-app-<version>-win-x64.msi`
- `distraction-firewall-runtime-<version>-win-x64.msi`
- `distraction-firewall-setup-<version>-win-x64.exe`

The App MSI owns only `Program Files\Distraction Firewall\`, including the UI,
CLI, and Start menu shortcut. The hidden Runtime MSI owns only
`Program Files\Distraction Firewall Lease Runtime\` and the protected
`ProgramData\DistractionFirewall\Runtime\v1` state tree. It installs
`DistractionFirewallActivation` as a delayed automatic LocalSystem service with
the exact `--service` argument and restart-on-failure policy. The Runtime MSI
also seeds the 64-bit owner/product registry values and the empty
`dns\observations\observed-addresses.json` store; the service, not MSI, creates
the per-lease target snapshot.

## Version 0.1 owner-account contract

Version 0.1 supports installation only when Setup is launched by the same
signed-in Windows user who will later run the unelevated App. On a new Runtime
install, the MSI requires `UserSID` and rejects LocalSystem, LocalService,
NetworkService, and the same broad/well-known principals rejected by Runtime
settings bootstrap. Administrative-image creation and maintenance of an
already-installed product remain available.

System-management deployment and over-the-shoulder elevation with credentials
for a different administrator account are not supported in Version 0.1. They
must not be used to infer or provision the App owner. A future managed-install
design needs a separately authenticated, secure owner-SID input and is outside
this release contract.

## Active-lease removal contract

The Runtime MSI has two guards. An early fixed-path AppSearch rejects an already
active install, upgrade, repair, patch, or uninstall. A second checked,
deferred, non-impersonated custom action runs the installed finalizer after
`StopServices` and before `DeleteServices`/`RemoveFiles`. It acquires the
capsule-store lock and fails closed if `active-lease.json` exists. For a full
Runtime removal, a following checked finalizer action re-runs that guard and
CAS-removes only owned WFP and Task Scheduler installation objects. A failed
transaction is expected to roll the previously running service back. The
isolated Windows 11 smoke job is designed to verify that behavior, but no real
Windows 11 evidence has been recorded yet.

Inactive Runtime uninstall recursively removes only the installer-owned v1 data
root obtained from the protected 64-bit registry seed. Active rejection leaves
the service, payload, registry, and ProgramData state intact. App uninstall
never removes Runtime.

Burn installs Runtime before App and uninstalls in reverse order. Its chain uses
`DisableRollback="yes"`: when Runtime removal is refused during an active lease,
App remains removed instead of being restored. The same choice means a failed
installation can leave Runtime installed; rerunning Setup is the supported
recovery path.

## Verification and release

`eng/verify-installer.ps1` checks WiX source, MSI tables and sequencing, x64/Win11
launch conditions, service configuration, ACLs, registry ownership, an
administrative-image extraction, extracted Burn attached-payload hashes, and optional
Authenticode signatures. The hosted release workflow runs format, build, tests,
publish, packaging, installer validation, checksum generation, and an SPDX
distribution-inventory skeleton before creating a draft GitHub prerelease.

`workflow_dispatch` can run the destructive smoke test only on a disposable,
elevated, clean runner labelled `[self-hosted, Windows, X64, windows-11]`. It
validates install and diagnose, synthetic-marker early active-removal refusal
with service/payload preservation, App-only uninstall, and inactive Runtime
cleanup. Because the marker exists before MSI starts, this does not prove the
deferred guard's rollback restart or reproduce a real activation/uninstall
race. This manual job is not a dependency of alpha tag packaging, and no
real-run evidence has been obtained yet.

Alpha artifacts may be unsigned. Optional Authenticode signing uses
`WINDOWS_SIGNING_CONFIGURED=true`, `WINDOWS_SIGNING_TIMESTAMP_URL`, and the
`WINDOWS_SIGNING_PFX_BASE64` / `WINDOWS_SIGNING_PFX_PASSWORD` secrets. The PFX
is imported non-exportable on the ephemeral runner, deleted immediately, and
the imported certificate is removed after use. Stable packaging mechanically
checks valid signatures on the two outer MSIs and Setup EXE plus
`implemented=true` with a nonempty evidence array for deferred uninstall. It
does not assess evidence quality, sign inner PE payloads, or constitute release
approval.

The remaining deferred capability is automatic Runtime/Bundle removal after an
active lease deadline, together with destructive VM evidence. Until that gate
is complete, active removal is refused and must be retried after lease expiry.
The generated SPDX file is an artifact inventory, not a full dependency SBOM.

## Alpha limitations

The package has not yet been validated on a real Windows 11 client. An initial
set of zero public target IPs fails activation with `ActivationFailed`. Seed
discovery covers only the exact and `www` target hostnames, not every
`googlevideo` hostname; it is a floor, not a coverage guarantee. If the public
target-IP set later falls to zero during an Active lease, health becomes
`Degraded`. Immediate termination of dynamic YouTube CDN connections already
established at activation is not proven. A changed DHCP resolver on an already
owned interface is not refreshed during an active lease; only the initial
snapshot and newly discovered interfaces are used.

Stable tags produce a stable-candidate draft only. Publication is prohibited
until inner PE signing/verification, destructive network E2E, complete SBOM,
provenance/attestation, and reviewed Windows 11 evidence are in place.
