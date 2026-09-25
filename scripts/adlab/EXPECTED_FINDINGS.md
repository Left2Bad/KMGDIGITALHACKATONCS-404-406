# Expected findings in the isolated AD lab

**FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.**

`ExpectedFindings.psd1` is the machine-readable minimum RuleId manifest. The table below explains the evidence to inspect after a real ScanRun. Check that each listed RuleId is **present** on the named object; other findings may legitimately appear. Do not assert a fixed AD Security Score.

| Object | Lab configuration | Expected RuleId | Important evidence |
| --- | --- | --- | --- |
| `lab_clean_user` | Enabled ordinary account | No scenario-specific RuleId | No lab-injected privilege, SPN, delegation, or PNE |
| `lab_expired_user` | Expiration set to yesterday | `IRA-ACCOUNT-002` | Expiration precedes scan time |
| `lab_pne_user` | Password never expires | `IRA-PASSWORD-001` | `DONT_EXPIRE_PASSWORD` |
| `svc_sql` | Unique `MSSQLSvc/sql01.adlab.test:1433` SPN and PNE | `IRA-PASSWORD-001`, `IRA-SERVICE-001` | SPN-based service classification and PNE |
| `lab_direct_admin` | Direct Backup Operators member | `IRA-PRIV-001` | Direct, depth 1, Backup Operators |
| `lab_nested_admin` | DemoHelpDesk → DemoITAdmins → Domain Admins | `IRA-PRIV-002` | Full nested path and depth 3 |
| `lab_multi_admin` | Direct Backup Operators and Server Operators member | `IRA-PRIV-001`, `IRA-PRIV-003` | Two direct privileged roles (possibly two `IRA-PRIV-001` rows) |
| `svc_unconstrained` | SPN and `TRUSTED_FOR_DELEGATION` | `IRA-DELEGATION-001` | Unconstrained UAC flag |
| `svc_constrained` | Unique account SPN and `msDS-AllowedToDelegateTo` | `IRA-DELEGATION-002` | Target `HTTP/app01.adlab.test` |
| `svc_protocol_trans` | Delegation target and `TRUSTED_TO_AUTH_FOR_DELEGATION` | `IRA-DELEGATION-003` | Target and UAC flag; no duplicate constrained classification |
| `svc_rbcd_target` | RBCD permits `svc_rbcd_source` | `IRA-DELEGATION-004` | RBCD attribute present; ACL details are not parsed by the app |
| `lab_locked_user` | Lab-only PSO plus actual failed authentication attempts | `IRA-ACCOUNT-003` | Current `LockedOut` and computed UAC `LOCKOUT` |
| `gmsa_demo` | Real `msDS-GroupManagedServiceAccount` object | No required finding | Snapshot `IsServiceAccount = true` |

`servicePrincipalName` identifies the account's own service endpoint; `msDS-AllowedToDelegateTo` lists target services for constrained delegation. They are different attributes. The service accounts may receive additional service-related findings according to current risk settings.

## Fresh-lab scenarios not synthetically seeded

- `IRA-ACCOUNT-001`: old `lastLogonTimestamp` is not deterministically seeded through supported administrative commands in a fresh domain.
- `IRA-PASSWORD-002`: arbitrary historical `pwdLastSet` is not written. AD sets it when passwords change.
- `IRA-SPN-001`: duplicate SPN is not forced; modern AD rejects duplicate originating writes. Forest-wide uniqueness is not weakened.
- `IRA-AD-001`: SIDHistory is not forged. It requires a legitimate migration scenario.

These rules remain implemented and covered by automated .NET tests. No DC clock changes, `dSHeuristics` changes, or direct binary security descriptor edits are used.
