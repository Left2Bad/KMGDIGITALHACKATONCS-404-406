# Isolated Windows Server AD test lab

**FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.**

These scripts create intentionally unsafe accounts and a short Domain Admin membership chain. Run them only on a disposable, isolated **Windows Server 2022** VM named `DC01` (Windows Server 2019+ is supported) with a static IP, working DNS, Windows PowerShell 5.1, and local administrator access. The lab is one AD DS + DNS domain controller for `adlab.test` (`ADLAB`). Take a VM snapshot before promotion and before risk scenarios. Do not join this VM to a production forest.

`LabConfig.ps1` is the single source for the domain, host, OU, scanner, and PSO names. All mutation scripts require an exact domain and single-DC check. They run locally on DC01. Ordinary test accounts and groups are confined to `OU=HackathonLab`; only documented memberships in built-in groups and the lab-only PSO/KDS key touch domain-level configuration. Setup scripts converge existing lab objects instead of creating duplicates. They refuse to modify an account or group with the expected SAM name outside the lab OU.

## Order of execution

Open **elevated Windows PowerShell 5.1** on the isolated VM. Use a domain administrator after promotion. The scripts stop on errors. Password prompts use `SecureString` and are never printed or stored in this repository.
If local script execution is blocked and your lab policy permits it, set `RemoteSigned` for the current PowerShell process only: `Set-ExecutionPolicy -Scope Process RemoteSigned`. Do not change machine-wide policy for this lab.

```powershell
cd C:\Path\To\IdentityRiskAnalyzer\scripts\adlab
.\01-Install-AdDsForest.ps1 -ConfirmLabInstall
# Promotion reboots the VM. Sign in again, then continue manually:
.\02-Create-LabStructure.ps1
.\03-Create-LabAccounts.ps1
.\04-Configure-RiskScenarios.ps1 -ConfirmLabChanges
.\05-Create-ScannerAccount.ps1
.\06-Verify-Lab.ps1
.\07-Print-AppConfiguration.ps1
```

Stage 01 installs AD DS and DNS and prompts for a DSRM password. There is no post-reboot scheduled task. Stage 02 creates `OU=HackathonLab` and its `Users`, `ServiceAccounts`, `Groups`, and `Servers` child OUs. Stage 03 prompts once for a strong default test-user password when new accounts are needed, then creates lab accounts/groups. Stage 04 creates the risk scenarios and a gMSA. Stage 05 asks for a **separate** scanner password and leaves the scanner as an ordinary Domain User. Re-running 02–06 should create no duplicate lab objects. Re-running 04 may renew the expired-account date and, if a 30-minute lockout has elapsed, make up to three further failed logons for the dedicated locked user.

If stage 04 cannot create a gMSA, it stops with an explicit error; inspect the KDS root key, functional level, and ActiveDirectory module before continuing. The script creates a backdated KDS root key **only when none exists and exactly one DC is present**. This is a Microsoft-documented shortcut for a single-DC test environment, not a production recommendation. `DemoGmsaHosts` grants the lab DC computer permission to retrieve the gMSA managed password; no Windows service installation is needed to test LDAP classification. The cleanup script deliberately retains the domain-level KDS key.

`lab_locked_user` has a dedicated `HackathonLab-LockoutPSO` (threshold 3, 30-minute duration, 10-minute observation window). Stage 04 attempts three actual bad LDAP Negotiate authentications and verifies both `LockedOut` and computed UAC `LOCKOUT`. It reports **FAILED TO PREPARE LOCKED ACCOUNT SCENARIO** if effective lockout is not observed. It does not fabricate `lockoutTime`.

SPNs are checked with a domain-wide AD query before `setspn.exe -S` adds them. This lab forest has one domain, and `setspn -S` performs an additional duplicate check during the write. A conflicting SPN stops the script; SPN uniqueness settings are never disabled. `HTTP/app01.adlab.test` is a delegation **target**, not an SPN assigned to the constrained accounts.

## Test objects

| OU | Objects |
| --- | --- |
| Users | `lab_clean_user`, `lab_expired_user`, `lab_pne_user`, `lab_direct_admin`, `lab_nested_admin`, `lab_multi_admin`, `lab_locked_user` |
| ServiceAccounts | `svc_sql`, `svc_unconstrained`, `svc_constrained`, `svc_protocol_transition`, `svc_rbcd_source`, `svc_rbcd_target`, `svc_ira_scanner`, `gmsa_demo` |
| Groups | `DemoHelpDesk`, `DemoITAdmins`, `DemoGmsaHosts` |
| Servers | Empty OU reserved for lab organization |

Built-in `Backup Operators`, `Server Operators`, and `Domain Admins` are existing domain groups outside the lab OU. `lab_direct_admin` joins Backup Operators. `lab_multi_admin` joins Backup Operators and Server Operators. The nested path is `lab_nested_admin → DemoHelpDesk → DemoITAdmins → Domain Admins` (depth 3). Only `DemoITAdmins` is added to Domain Admins.

For delegation, `svc_unconstrained` has a unique SPN and `TRUSTED_FOR_DELEGATION`. `svc_constrained` has a unique SPN and `msDS-AllowedToDelegateTo = HTTP/app01.adlab.test`. `svc_protocol_transition` has that target and `TRUSTED_TO_AUTH_FOR_DELEGATION`. `svc_rbcd_target` uses the supported `PrincipalsAllowedToDelegateToAccount` parameter to allow `svc_rbcd_source`; the script does not handcraft a binary security descriptor. See [EXPECTED_FINDINGS.md](EXPECTED_FINDINGS.md) and the machine-readable `ExpectedFindings.psd1` for required RuleIds and evidence.

## Connect Identity Risk Analyzer

Run the app on a host that can resolve `dc01.adlab.test` and reach TCP 389. Check `Resolve-DnsName dc01.adlab.test` and `Test-NetConnection dc01.adlab.test -Port 389`. Use `07-Print-AppConfiguration.ps1` for non-secret values. Configure the app's `ActiveDirectory` section with `Server=dc01.adlab.test`, `Port=389`, `UseSsl=false`, and **`BaseDn=DC=adlab,DC=test`**. The domain Base DN is needed to include the built-in privileged groups; limiting it to `OU=HackathonLab` would hide Domain Admins from graph analysis. The separate P1-17 stage below adds LDAPS without changing this LDAP workflow.

From the repository root on the application host, set credentials through User Secrets for development:

```powershell
dotnet user-secrets set "ActiveDirectory:Username" "ADLAB\svc_ira_scanner" --project src/IdentityRiskAnalyzer.Web
dotnet user-secrets set "ActiveDirectory:Password" "<scanner password>" --project src/IdentityRiskAnalyzer.Web
```

Replace the placeholder interactively; never commit the password, print it, or put it in `appsettings.json`. `LabSecrets.local.ps1` is ignored by git if an operator chooses to create one, but the scripts do not require a secrets file. The scanner is enabled, has a password, and has only standard Domain User directory read access; it is not placed in Domain Admins, Enterprise Admins, Administrators, or other configured administrative groups. Verify actual read access with the application before granting any additional permissions.

## End-to-end acceptance

1. Run stages 01–05 and require all rows in `06-Verify-Lab.ps1` to be `OK`. This verifier reads current AD properties and memberships and makes no changes.
2. Open `/ActiveDirectory` and run **Test Connection** using scanner credentials and LDAP 389 + Negotiate.
3. Open `/ActiveDirectory/Users` and `/ActiveDirectory/Groups`; confirm actual lab objects appear.
4. Open `/Scans`, select **Start Scan**, then open `/` and the historical scan details. A successful scan should be `Completed` or `CompletedWithErrors` with a score in 0–100. Do not require an exact score.
5. Compare the saved findings for each object against [EXPECTED_FINDINGS.md](EXPECTED_FINDINGS.md). Match required RuleIds by presence; extra findings may be valid. Verify nonzero findings, privileged accounts, service accounts, and Top Risky Accounts.
6. In historical account details, inspect the full `lab_nested_admin → DemoHelpDesk → DemoITAdmins → Domain Admins` path and `svc_constrained` target `HTTP/app01.adlab.test`. Confirm `svc_sql` and `gmsa_demo` have `IsServiceAccount = true`.
7. Download Accounts CSV and Findings CSV. Confirm they open, contain the test accounts, match the persisted findings, and preserve Cyrillic text if present.
8. Re-run stages 02–06 and confirm no duplicate lab objects. The verifier may report a locked-user failure after the timed lockout expires; rerun stage 04 to restore it before another scan.

## Fresh-lab scenarios not synthetically seeded

Stale account detection is implemented and unit-tested, but a realistic old `lastLogonTimestamp` cannot be deterministically seeded in a fresh lab through supported administrative commands. Likewise, an arbitrary old `pwdLastSet` is not written. Modern AD may reject duplicate SPN writes, so `IRA-SPN-001` remains unit-tested instead of being a mandatory real-AD scenario. SIDHistory is not seeded without a legitimate migration. The scripts do not change the DC clock, bypass forest-wide SPN uniqueness, or write unsupported SIDHistory data.

## P1-17 — LDAPS (separate optional stage)

**FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.** Keep stages 01–07 usable with LDAP 389. On this disposable, single-DC VM only, the CA and DC may share one server to simplify the demo; this is **not** a recommended production CA architecture. Run these commands after the P1-16 lab is verified:

```powershell
.\08-Install-LabCertificateAuthority.ps1 -ConfirmLabCaInstall
.\09-Configure-DcLdapsCertificate.ps1
# Restart DC01 manually if AD DS has not picked up the new certificate.
$scanner = Get-Credential 'ADLAB\svc_ira_scanner'
.\10-Verify-Ldaps.ps1 -Credential $scanner
.\07-Print-AppConfiguration.ps1 -Ldaps
```

Stage 08 installs the AD CS Certification Authority role only if missing, then configures the expected Enterprise Root CA `ADLAB-Lab-Root-CA`. It detects an existing CA and refuses to replace a differently named CA. It never exports a private key. Stage 09 publishes the built-in `DomainControllerAuthentication` template if needed, enrolls the DC machine through `certreq -enroll -machine`, and inspects `Local Computer\Personal`. It skips enrollment if a suitable certificate exists; it does not remove unknown certificates. If a possible LDAPS certificate exists but fails checks, resolve it manually before adding another. [Microsoft's LDAPS requirements](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-over-ssl-3rd-certification-authority) include Server Authentication EKU `1.3.6.1.5.5.7.3.1`, DC FQDN in DNS SAN or subject CN, private key, valid dates, and a trusted chain. AD DS can prefer an NTDS service-store certificate over the Local Computer store; inspect that store if observed LDAPS behavior differs from the selected local certificate.

Stage 10 reads current AD and certificate properties without changing them. It reports DNS resolution, TCP 636, certificate presence, private key, Server Authentication EKU, hostname/SAN, dates, and chain. Passing `-Credential` additionally performs an actual LDAPS TLS bind and Base DN query with the scanner account; without credentials that row says **NOT TESTED**. Multiple potential certificates produce a warning. `Test-NetConnection dc01.adlab.test -Port 636` checks only transport availability and **does not prove certificate validity**. If certificate enrollment has succeeded but LDAPS does not work, restart DC01 deliberately, then rerun stage 10. The scripts do not reboot it automatically.

On the DC, open `ldp.exe` → **Connection** → **Connect**, set **Server** to `dc01.adlab.test`, **Port** to `636`, and check **SSL**. A successful connection should display RootDSE. This manual test and the application Test Connection are required because a certificate lying in the store is not itself proof of working LDAPS.

The application host must trust the **public** root CA certificate. On a separate Windows application machine, export only the public root from the lab CA, for example `certutil -ca.cert C:\Temp\adlab-root-ca.cer`, copy that `.cer`, and import it into **Local Computer → Trusted Root Certification Authorities** (or use the host's managed certificate deployment). Do **not** copy a PFX, private key, or CA backup to the app host. When the app runs on the DC, check local root trust as well. On Linux/macOS, install the public CA in that operating system's system trust store. Generated `.cer` files are ignored in `scripts/adlab` by default; private-key formats are ignored repository-wide.

Configure `ActiveDirectory:Server=dc01.adlab.test`, `Port=636`, `UseSsl=true`, `BaseDn=DC=adlab,DC=test`. Keep `ADLAB\svc_ira_scanner` in User Secrets or protected environment configuration. `UseSsl=true` means immediate LDAPS, not StartTLS. The shared `LdapConnection` setup is used by Test Connection, users, groups, managed service accounts, and group-member range retrieval. Do not switch to an IP if the certificate names only `dc01.adlab.test`.

After stage 10, run `/ActiveDirectory` → **Test Connection**, open Users and Groups diagnostics, then start a real `/Scans` run and inspect the saved Dashboard. For a negative certificate-name check, use a temporary DNS alias such as `dc01-alias.adlab.test` that resolves to the same DC but is absent from the certificate's SAN/CN. Test Connection must fail; restore `dc01.adlab.test` and retry. An IP address is rejected by the application's LDAPS configuration validation and is therefore not a TLS-name-validation test. On a separate application VM without the lab CA in its root trust store, the LDAPS test must fail; after installing **only the public** root certificate, it should pass. Do not add a certificate-validation bypass to make either negative case pass. The scripts do not seed expired certificates or automatically remove trusted roots.

## Cleanup

### Optional P1-18 Security Event Log access

**FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.** After stage 05, an elevated operator on DC01 may run `.\11-Configure-EventLogReader.ps1 -ConfirmOptionalEventLogAccess` to add only `svc_ira_scanner` to built-in **Event Log Readers**. The script checks the fixed lab domain and DC before changing membership, and repeated runs are idempotent. Refresh the scanner logon session before testing remote Security log access. Set `SecurityEventLog:Enabled=true` on the application host only when this optional inventory is desired. It is read-only; do not use a generic credential attack tool to generate test failures. Cleanup removes this optional external group membership before deleting the lab OU.

```powershell
.\99-Remove-LabObjects.ps1 -ConfirmLabCleanup
```

The cleanup requires the exact `adlab.test` single-DC topology, the exact `OU=HackathonLab,DC=adlab,DC=test` target, and an interactive typed confirmation. It first removes only documented memberships from Domain Admins, Backup Operators, and Server Operators. It then removes only `HackathonLab-LockoutPSO` and the lab OU subtree. It does **not** remove the KDS root key, the optional P1-17 CA/certificates, demote the DC, remove AD DS, or destroy the domain/VM. For complete removal, revert or delete the isolated VM snapshot/VM.

## Reference

- [Microsoft: KDS root key in a single-DC test environment](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key)
- [Microsoft: New-ADServiceAccount](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adserviceaccount)
- [Microsoft: Set-ADAccountControl](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountcontrol)
- [Microsoft: fine-grained password policy subjects](https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adfinegrainedpasswordpolicysubject)
