# Изолированная тестовая среда AD на Windows Server

**ТОЛЬКО ДЛЯ ИЗОЛИРОВАННОЙ ТЕСТОВОЙ ACTIVE DIRECTORY. НЕ ЗАПУСКАТЬ В ПРОИЗВОДСТВЕННОМ ДОМЕНЕ.**

Скрипты создают намеренно небезопасные аккаунты и цепочку членства в Domain Admins. Используйте только одноразовую изолированную **Windows Server 2022** VM с именем `DC01` (поддерживается Server 2019+), статическим IP, рабочим DNS, PowerShell 5.1 и локальными правами администратора. Лаборатория — один контроллер AD DS + DNS домена `adlab.test` (`ADLAB`). Сделайте снимок VM до повышения до DC и до настройки сценариев. Не присоединяйте VM к производственному forest.

`LabConfig.ps1` — единый источник имён домена, узла, OU, scanner и PSO. Скрипты изменения проверяют точное имя домена и наличие единственного DC, и запускаются локально на DC01. Обычные тестовые объекты размещаются в `OU=HackathonLab`; только документированные членства во встроенных группах, lab-only PSO и KDS key затрагивают конфигурацию домена. Повторный запуск приводит объекты в нужное состояние и не создаёт копий. Объект с ожидаемым SAM-именем вне лабораторной OU изменяться не будет.

## Порядок запуска

Откройте на изолированной VM **Windows PowerShell 5.1 с повышенными правами**. Используйте доменного администратора. Скрипты останавливаются при ошибках. Пароли вводятся как `SecureString`, не печатаются и не сохраняются в репозитории. Если политика лаборатории разрешает, но блокирует локальные скрипты, задайте `RemoteSigned` только для текущего процесса PowerShell, не меняя системную политику.

```powershell
cd C:\Path\To\IdentityRiskAnalyzer\scripts\adlab
.\01-Install-AdDsForest.ps1 -ConfirmLabInstall
# Promotion перезагрузит VM. Войдите снова и продолжите вручную:
.\02-Create-LabStructure.ps1
.\03-Create-LabAccounts.ps1
.\04-Configure-RiskScenarios.ps1 -ConfirmLabChanges
.\05-Create-ScannerAccount.ps1
.\06-Verify-Lab.ps1
.\07-Print-AppConfiguration.ps1
```

Этап 01 устанавливает AD DS и DNS, запрашивает DSRM password и перезагружает VM; автоматического продолжения нет. Этап 02 создаёт `OU=HackathonLab` и дочерние OU `Users`, `ServiceAccounts`, `Groups` и `Servers`. Этап 03 запрашивает сильный пароль тестовых пользователей, если нужны новые аккаунты. Этап 04 настраивает риск-сценарии и gMSA. Этап 05 запрашивает отдельный пароль scanner и создаёт обычный Domain User. Повтор этапов 02–06 не создаёт дубликаты. Этап 04 может обновить дату истечения аккаунта и после истечения 30-минутной блокировки выполнить до трёх новых неудачных входов для выделенного locked user.

Если gMSA создать не удалось, этап 04 остановится. Проверьте KDS root key, функциональный уровень домена и модуль ActiveDirectory. KDS root key с временем действия в прошлом создаётся только при отсутствии ключа и ровно одном DC. Это документированный приём для одноузловой тестовой среды, не рекомендация для production. `DemoGmsaHosts` даёт компьютеру DC право получить управляемый пароль gMSA. Устанавливать Windows-службу не нужно. Cleanup сохраняет KDS key домена.

Для `lab_locked_user` создаётся отдельная Fine-Grained Password Policy `HackathonLab-LockoutPSO`: порог 3, блокировка 30 минут, окно наблюдения 10 минут. Этап 04 делает три настоящие неудачные LDAP Negotiate-аутентификации и проверяет `LockedOut` и UAC-флаг `LOCKOUT`. Если блокировка не подтверждена, выводится **FAILED TO PREPARE LOCKED ACCOUNT SCENARIO**. `lockoutTime` не подделывается.

До добавления SPN выполняется поиск по всему домену; используется `setspn.exe -S`, который также проверяет дубликаты. При конфликте скрипт останавливается. Уникальность SPN не отключается. `HTTP/app01.adlab.test` — цель delegation, а не SPN constrained-аккаунта.

## Тестовые объекты

| OU | Объекты |
| --- | --- |
| Users | `lab_clean_user`, `lab_expired_user`, `lab_pne_user`, `lab_direct_admin`, `lab_nested_admin`, `lab_multi_admin`, `lab_locked_user` |
| ServiceAccounts | `svc_sql`, `svc_unconstrained`, `svc_constrained`, `svc_protocol_trans`, `svc_rbcd_source`, `svc_rbcd_target`, `svc_ira_scanner`, `gmsa_demo` |
| Groups | `DemoHelpDesk`, `DemoITAdmins`, `DemoGmsaHosts` |
| Servers | Пустая OU для будущей структуры |

Встроенные `Backup Operators`, `Server Operators` и `Domain Admins` находятся вне lab OU. `lab_direct_admin` входит в Backup Operators; `lab_multi_admin` — в Backup Operators и Server Operators. Вложенный путь: `lab_nested_admin → DemoHelpDesk → DemoITAdmins → Domain Admins` (глубина 3). В Domain Admins добавляется только `DemoITAdmins`.

`svc_unconstrained` имеет уникальный SPN и флаг `TRUSTED_FOR_DELEGATION`. У `svc_constrained` настроен SPN и `msDS-AllowedToDelegateTo = HTTP/app01.adlab.test`. У `svc_protocol_trans` настроена та же цель и флаг `TRUSTED_TO_AUTH_FOR_DELEGATION`. Для `svc_rbcd_target` через `PrincipalsAllowedToDelegateToAccount` разрешается delegation от `svc_rbcd_source`; бинарный descriptor вручную не создаётся. Обязательные RuleId и evidence приведены в [EXPECTED_FINDINGS.md](EXPECTED_FINDINGS.md) и машиночитаемом `ExpectedFindings.psd1`.

## Подключение Identity Risk Analyzer

Узел приложения должен разрешать `dc01.adlab.test` и иметь доступ к TCP 389. Проверьте `Resolve-DnsName dc01.adlab.test` и `Test-NetConnection dc01.adlab.test -Port 389`. `07-Print-AppConfiguration.ps1` выводит несекретные настройки. Укажите `Server=dc01.adlab.test`, `Port=389`, `UseSsl=false` и **`BaseDn=DC=adlab,DC=test`**. Нужен DN всего домена, чтобы включить встроенные привилегированные группы; `OU=HackathonLab` скроет Domain Admins от анализа. LDAPS настраивается отдельно на P1-17.

На узле приложения, из корня репозитория, настройте User Secrets:

```powershell
dotnet user-secrets set "ActiveDirectory:Username" "ADLAB\svc_ira_scanner" --project src/IdentityRiskAnalyzer.Web
dotnet user-secrets set "ActiveDirectory:Password" "<scanner password>" --project src/IdentityRiskAnalyzer.Web
```

Замените placeholder при вводе; пароль не коммитьте и не помещайте в `appsettings.json`. Необязательный `LabSecrets.local.ps1` игнорируется git, но скриптам не нужен. Scanner включён, имеет пароль и обычный доступ Domain User на чтение каталога. Он не входит в Domain Admins, Enterprise Admins, Administrators или другие настроенные административные группы. Сначала проверьте чтение через приложение и лишь затем выясняйте необходимость дополнительных прав.

## Сквозная проверка

1. Запустите этапы 01–05; все строки `06-Verify-Lab.ps1` должны быть `OK`. Скрипт читает настоящие свойства и членства AD, ничего не меняя.
2. На `/ActiveDirectory` проверьте **Test Connection** учётными данными scanner через LDAP 389 + Negotiate.
3. На `/ActiveDirectory/Users` и `/ActiveDirectory/Groups` проверьте наличие лабораторных объектов.
4. В `/Scans` выберите **Start Scan**, затем проверьте `/` и исторические детали. Ожидается `Completed` или `CompletedWithErrors` и оценка 0–100; точная оценка не фиксируется.
5. Сверьте сохранённые findings с [EXPECTED_FINDINGS.md](EXPECTED_FINDINGS.md): проверьте обязательные RuleId, допускаются дополнительные findings. Убедитесь в наличии findings, привилегированных аккаунтов, сервисных аккаунтов и Top Risky Accounts.
6. Проверьте путь `lab_nested_admin → DemoHelpDesk → DemoITAdmins → Domain Admins` и цель `HTTP/app01.adlab.test` у `svc_constrained`. В снимке `svc_sql` и `gmsa_demo` должны иметь `IsServiceAccount = true`.
7. Скачайте Accounts CSV и Findings CSV. Убедитесь, что они открываются, содержат тестовые аккаунты, совпадают с сохранёнными findings и сохраняют кириллицу, если она есть.
8. Повторите этапы 02–06 и проверьте отсутствие копий. После тайм-аута блокировки проверка locked user может не пройти; повторите этап 04.

## Сценарии, которые не создаются искусственно

Обнаружение устаревших аккаунтов реализовано и покрыто unit tests, но штатными административными командами нельзя детерминированно записать правдоподобный старый `lastLogonTimestamp` в свежей лаборатории. Произвольный старый `pwdLastSet` также не записывается. Современная AD может отклонить дублирующий SPN, поэтому `IRA-SPN-001` проверяется unit tests и не обязателен для настоящего AD. SIDHistory не создаётся без легитимной миграции. Скрипты не переводят часы DC, не отключают уникальность SPN forest и не записывают SIDHistory неподдерживаемым способом.

## P1-17 — LDAPS (отдельный необязательный этап)

**ТОЛЬКО ДЛЯ ИЗОЛИРОВАННОЙ ТЕСТОВОЙ ACTIVE DIRECTORY. НЕ ЗАПУСКАТЬ В ПРОИЗВОДСТВЕННОМ ДОМЕНЕ.** Этапы 01–07 должны продолжать работать с LDAP 389. Только на одноразовой VM с единственным DC CA и DC можно разместить на одной машине ради демонстрации; это **не** рекомендуемая архитектура CA для production.

```powershell
.\08-Install-LabCertificateAuthority.ps1 -ConfirmLabCaInstall
.\09-Configure-DcLdapsCertificate.ps1
# Перезагрузите DC01 вручную, если AD DS не подхватил сертификат.
$scanner = Get-Credential 'ADLAB\svc_ira_scanner'
.\10-Verify-Ldaps.ps1 -Credential $scanner
.\07-Print-AppConfiguration.ps1 -Ldaps
```

Этап 08 устанавливает роль AD CS CA, если её нет, и настраивает ожидаемый Enterprise Root CA `ADLAB-Lab-Root-CA`. Другой существующий CA не заменяется. Закрытый ключ не экспортируется. Этап 09 при необходимости публикует шаблон `DomainControllerAuthentication`, запрашивает сертификат компьютера DC через `certreq -enroll -machine` и проверяет `Local Computer\Personal`. Подходящий сертификат повторно не выпускается, неизвестные сертификаты не удаляются. Если сертификат LDAPS не проходит проверку, исправьте причину вручную до повторного выпуска. [Требования Microsoft к LDAPS](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-over-ssl-3rd-certification-authority): EKU Server Authentication `1.3.6.1.5.5.7.3.1`, FQDN DC в DNS SAN или subject CN, закрытый ключ, допустимый срок и доверенная цепочка. AD DS может выбрать сертификат хранилища службы NTDS вместо Local Computer; проверьте его, если LDAPS ведёт себя иначе ожидаемого.

Этап 10 только читает AD и сертификаты: проверяет DNS, TCP 636, наличие сертификата и закрытого ключа, EKU, hostname/SAN, сроки и цепочку. С `-Credential` выполняется настоящий LDAPS TLS bind и запрос Base DN под scanner; без credentials отображается **NOT TESTED**. Несколько потенциальных сертификатов дают предупреждение. `Test-NetConnection dc01.adlab.test -Port 636` проверяет транспорт, но **не сертификат**. Если выпуск прошёл, а LDAPS нет, вручную перезагрузите DC01 и повторите этап 10; скрипты не перезагружают его автоматически.

Для ручной проверки на DC откройте `ldp.exe` → **Connection** → **Connect**, задайте сервер `dc01.adlab.test`, порт `636` и включите **SSL**. При успехе отображается RootDSE. Успешного наличия сертификата недостаточно: нужны эта проверка и Test Connection приложения.

Хост приложения должен доверять **публичному** корню CA. На отдельной Windows-машине экспортируйте только публичный сертификат командой, например, `certutil -ca.cert C:\Temp\adlab-root-ca.cer`, и импортируйте `.cer` в **Local Computer → Trusted Root Certification Authorities** либо используйте управляемую доставку сертификата. Не копируйте PFX, закрытый ключ или backup CA на приложение. Если приложение работает на DC, проверьте локальное доверие. В Linux/macOS добавьте публичный сертификат в системное хранилище доверия. `.cer` игнорируются в `scripts/adlab`; форматы с закрытым ключом игнорируются во всём репозитории.

Задайте `ActiveDirectory:Server=dc01.adlab.test`, `Port=636`, `UseSsl=true`, `BaseDn=DC=adlab,DC=test`. Храните `ADLAB\svc_ira_scanner` в User Secrets или защищённой конфигурации. `UseSsl=true` означает прямой LDAPS, не StartTLS. Общая настройка `LdapConnection` используется для Test Connection, пользователей, групп, MSA и получения диапазонов участников групп. Не используйте IP, если сертификат выпущен для `dc01.adlab.test`.

После этапа 10 повторите Test Connection, страницы Users/Groups, ScanRun и проверьте Dashboard. Для проверки отказа из-за имени используйте временный DNS alias `dc01-alias.adlab.test`, ведущий на DC, но отсутствующий в SAN/CN сертификата. Test Connection должен завершиться ошибкой; верните `dc01.adlab.test` и повторите. IP не подходит для этого теста: конфигурация LDAPS отклоняет его раньше проверки имени. На отдельной VM без корневого CA LDAPS должен завершиться ошибкой; после установки только публичного сертификата — пройти. Не обходите проверку сертификата. Скрипты не создают просроченные сертификаты и автоматически не удаляют доверенные корни.

## Необязательный доступ к Security Event Log (P1-18)

**ТОЛЬКО ДЛЯ ИЗОЛИРОВАННОЙ ТЕСТОВОЙ ACTIVE DIRECTORY. НЕ ЗАПУСКАТЬ В ПРОИЗВОДСТВЕННОМ ДОМЕНЕ.** После этапа 05 оператор на DC01 может выполнить в повышенной сессии `.\11-Configure-EventLogReader.ps1 -ConfirmOptionalEventLogAccess`. Скрипт проверит фиксированный домен и DC и добавит только `svc_ira_scanner` во встроенную группу **Event Log Readers**. Он идемпотентен. Обновите сеанс scanner перед проверкой удалённого чтения. На приложении задайте `SecurityEventLog:Enabled=true` только при использовании этой функции. Не запускайте универсальные инструменты перебора credentials для создания событий. Cleanup снимает это внешнее членство перед удалением OU.

## Очистка

```powershell
.\99-Remove-LabObjects.ps1 -ConfirmLabCleanup
```

Очистка требует точной одноузловой лаборатории `adlab.test`, пути `OU=HackathonLab,DC=adlab,DC=test` и подтверждения вводом заданной строки. Сначала удаляются только задокументированные членства в Domain Admins, Backup Operators, Server Operators и Event Log Readers; затем `HackathonLab-LockoutPSO` и подраздел лабораторной OU. KDS root key, CA/сертификаты P1-17, AD DS, домен и VM не удаляются, DC не демонтируется. Для полного удаления восстановите снимок или удалите изолированную VM.

## Справочные материалы

- [Microsoft: KDS root key для тестовой среды с одним DC](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key)
- [Microsoft: New-ADServiceAccount](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adserviceaccount)
- [Microsoft: Set-ADAccountControl](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountcontrol)
- [Microsoft: субъекты Fine-Grained Password Policy](https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adfinegrainedpasswordpolicysubject)
