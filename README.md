# Identity Risk Analyzer — инструкция от первого запуска до демонстрации

Это руководство рассчитано на человека, который умеет пользоваться Windows и PowerShell, но раньше не настраивал Active Directory. Сначала создайте **изолированную лабораторию**, подключите приложение по обычному LDAP на порту 389, выполните настоящий scan и проверьте результаты. LDAPS и Security Event Log оставлены отдельными дополнительными главами.

> [!CAUTION]
> ## Скрипты лаборатории нельзя запускать в production Active Directory
>
> **FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.**
>
> Скрипты намеренно создают истёкшие и заблокированные учётные записи, настройки Kerberos delegation и членство через вложенные группы в `Domain Admins`. Запускайте их только внутри выделенной одноузловой VM с новым доменом `adlab.test`, который не связан с рабочим доменом организации. В приложении нет кнопок исправления AD, но лабораторные PowerShell-скрипты изменяют AD.

## Быстрый маршрут

1. Установить .NET 10 SDK и VirtualBox.
2. Создать отдельную Windows Server 2022 VM `DC01` с сетью **Host-only**.
3. Создать домен `adlab.test` и запустить лабораторные скрипты по порядку.
4. На основном ПК сохранить адрес DC и учётные данные `svc_ira_scanner` в User Secrets.
5. Проверить `/ActiveDirectory`, затем `/ActiveDirectory/Users` и `/ActiveDirectory/Groups`.
6. В `/Scans` запустить **Start Scan**, проверить сохранённый scan на Dashboard, открыть исторические детали и скачать два CSV.

Сначала доведите до конца обычный LDAP 389. К необязательным главам про LDAPS и Security Event Log переходите только после успешного основного scan.

## Что такое Identity Risk Analyzer

**Identity Risk Analyzer** — веб-приложение для чтения и анализа конфигурации Microsoft Active Directory. Оно собирает сведения об учётных записях и группах, ищет потенциально рискованные настройки и объясняет находки. Приложение работает в режиме чтения: оно не выключает учётные записи и не меняет членство групп.

```text
Windows Server с Active Directory
              │
              │ LDAP 389 или LDAPS 636 (только чтение)
              ▼
Identity Risk Analyzer (ASP.NET Core MVC)
              │
              ├─ пользователи, группы, вложенное членство
              ├─ privileged paths, service accounts, delegation
              ├─ Risk Rules и Risk Score
              ▼
         SQLite snapshot
              │
              ├─ Dashboard и исторические детали
              └─ CSV Accounts / Findings
```

Сначала приложение читает Active Directory по LDAP. Затем строит связи пользователей и групп в памяти и запускает отдельные анализаторы: привилегированных групп, сервисных записей и Kerberos delegation. Risk Rules создают findings с объяснением, evidence и рекомендацией. Scoring присваивает оценку объектам. В конце результаты сохраняются в SQLite как отдельный ScanRun. Dashboard, исторические детали и CSV читают именно сохранённый снимок и не запускают новый LDAP-запрос при открытии.

### Слова, которые встретятся в инструкции

| Термин | Простое объяснение |
| --- | --- |
| Active Directory (AD) | Каталог организации: учётные записи, компьютеры и группы, которыми управляет Windows-домен. |
| AD DS | Служба Windows Server, которая хранит и обслуживает каталог Active Directory. |
| Domain Controller (DC) | Сервер, который хранит копию домена, проверяет вход пользователей и отвечает на запросы AD. В лаборатории это `DC01`. |
| Domain / домен | Общая область имён и учётных записей. Здесь это выдуманный тестовый домен `adlab.test`. |
| DNS | Служба, переводящая имя сервера в IP-адрес. Приложению нужно найти `dc01.adlab.test`. AD также использует DNS для обнаружения контроллеров домена. |
| LDAP | Протокол, через который приложение запрашивает объекты каталога. В основном сценарии используется LDAP на TCP 389 с Negotiate-аутентификацией. |
| LDAPS | LDAP, защищённый TLS-сертификатом, обычно на TCP 636. Одного открытого порта недостаточно: клиент должен доверять сертификату DC и проверять его имя. |
| DN / Base DN | DN — полный путь к объекту каталога. Base DN — корень поиска. `DC=adlab,DC=test` означает весь домен `adlab.test`. |
| OU | Организационная единица — папка внутри AD для упорядочивания объектов и ограничения области управления. Например, лабораторные users находятся в `OU=Users,OU=HackathonLab,...`. |
| `Domain Admins` | Встроенная административная группа домена. Её членство даёт очень широкие права на домен. В лаборатории в неё добавляется только группа `DemoITAdmins` для проверки nested path. |
| SPN | Service Principal Name — имя службы, связанное с учётной записью AD. SPN помогает Kerberos найти учётную запись, под которой работает служба. |
| Kerberos delegation | Настройка, позволяющая службе действовать от имени пользователя для других служб. Некоторые варианты требуют особенно тщательной проверки. |
| gMSA | Group Managed Service Account — сервисная учётная запись, пароль которой AD управляет автоматически. В лаборатории создаётся настоящий объект gMSA, но Windows-служба на нём не запускается. |
| AD CS / CA | AD CS — роль управления сертификатами в Windows Server; CA (Certification Authority) выпускает сертификаты. В необязательной LDAPS-главе лабораторная CA выдаёт сертификат DC. |
| Security Event Log | Журнал Windows Security. В нём могут быть события успешных/неуспешных входов и блокировок; чтение этой функции выключено по умолчанию. |
| Snapshot / ScanRun | Сохранённый результат одного запуска анализа. Следующий запуск создаёт новый снимок, не перезаписывая предыдущий. |

## Что именно нужно проверить перед Hackathon

### Уровень 1 — автоматические .NET tests

Это тесты кода. Они проверяют парсинг LDAP-атрибутов, граф групп, правила, scoring, SQLite и другие сценарии без настоящего контроллера домена. Запускайте команды **на основном ПК из корня repository**, то есть из папки, где лежит `IdentityRiskAnalyzer.sln`:

```powershell
dotnet restore
dotnet build
dotnet test
```

`restore` скачивает NuGet-зависимости, `build` компилирует решение, `test` запускает xUnit. Тесты могут пройти, даже если настоящего AD нет или настройки LDAP неверны. При проверке этого README прошло **254/254 теста, 0 пропущено**. При изменении ветки или добавлении тестов ориентируйтесь на итоговый summary самой команды `dotnet test`.

### Уровень 2 — соединение с настоящим тестовым Active Directory

Нужно поднять отдельную Windows Server VM, установить AD DS, создать лабораторные users/groups и проверить, что основной ПК видит DC через DNS и TCP 389. Этот уровень проверяет настоящее LDAP-соединение, credentials, Base DN и реальные ответы AD.

### Уровень 3 — сквозной End-to-End test

Главная проверка проекта:

```text
настоящий AD
  → LDAP collection
  → Start Scan
  → Risk Findings и Score
  → SQLite snapshot
  → Dashboard и historical account details
  → Accounts CSV и Findings CSV
```

Для демонстрации жюри нужен именно этот уровень: успешные unit tests сами по себе его не заменяют.

## Что установить перед началом

### На основном Windows ПК

* **.NET 10 SDK** — нужен для сборки и запуска приложения. Выберите SDK для Windows x64 на [официальной странице .NET 10](https://dotnet.microsoft.com/en-us/download/dotnet/10.0). Нужен именно SDK, а не только Runtime.
* **VirtualBox** — для этого tutorial выбран один основной вариант виртуализации. Установщик и руководство: [официальный сайт VirtualBox](https://www.virtualbox.org/) и [руководство VirtualBox](https://www.virtualbox.org/manual/).
* **Git** нужен только если вы будете клонировать repository. Если файлы проекта уже есть на диске, для выполнения команд ниже Git необязателен.
* IDE, например Visual Studio или VS Code, необязательна. Для этой инструкции достаточно Windows PowerShell и браузера.

Альтернативы VirtualBox: **Hyper-V** (доступность зависит от редакции Windows и включённой виртуализации) или **VMware Workstation**. Выберите **только один** вариант. Дальнейшие клики и названия сетевых параметров описаны для VirtualBox.

### Внутри VM

Используйте Windows Server 2022 с Desktop Experience (графическим интерфейсом); scripts заявляют поддержку Windows Server 2019 и новее, а 2022 — рекомендуемый вариант. ISO можно получить в [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2022). Установите английскую или русскую версию — команды используют имена AD-объектов по SID, но подписи Windows могут отличаться.

PowerShell 5.1 и модуль ActiveDirectory устанавливаются/добавляются серверными ролями и инструментами AD DS. Не устанавливайте на DC приложение, .NET SDK или IDE ради этой лаборатории: приложение запускается на основном ПК.

## Создание Windows Server VM

Потребуется включённая аппаратная виртуализация в BIOS/UEFI компьютера. Имена кнопок VirtualBox могут слегка отличаться между версиями.

1. Скачайте Windows Server 2022 Evaluation ISO с официального сайта Microsoft.
2. Установите VirtualBox и откройте **VirtualBox Manager**.
3. Нажмите **New**. Назовите VM `DC01`. Укажите тип Microsoft Windows и Windows Server 2022 (64-bit), если такой вариант доступен.
4. Выделите **8 GB RAM** и **2 CPU** как удобный минимум для демонстрационного сервера; если у компьютера достаточно ресурсов, используйте 4 CPU. Не отдавайте VM всю память и все ядра хоста.
5. Создайте новый виртуальный диск VDI, динамически выделяемый, размером **80 GB** (60 GB — нижняя практическая граница для этой лаборатории). Файл виртуального диска будет увеличиваться по мере использования.
6. В настройках VM откройте **Storage**, выберите виртуальный оптический привод и подключите скачанный ISO.
7. В настройках VM → **Network** пока подключите адаптер 1 к сети **Host-only**. Точная настройка приведена в следующем разделе. Не выбирайте Bridged Adapter.
8. Запустите VM. В установщике Windows выберите Windows Server 2022 Standard Evaluation **Desktop Experience**, примите лицензию, выберите Custom installation и пустой виртуальный диск.
9. После установки задайте пароль встроенному локальному `Administrator`. Сохраните его в менеджере паролей. Это пароль администратора сервера; он отличается от вводимого позже DSRM password.
10. Войдите в Windows Server. Откройте **Server Manager → Local Server**, нажмите ссылку рядом с **Computer name**, выберите **Change**, введите `DC01`, подтвердите и перезагрузите VM.
11. Сделайте снимок VM до установки домена, например `A - чистый сервер, DC01`: в VirtualBox выделите VM и выберите **Machine → Take Snapshot**, задайте имя и подтвердите. Snapshot — точка возврата всего виртуального диска и состояния VM.

`DC01` — имя нашего тестового контроллера домена. Лабораторные scripts проверяют, что они работают именно на компьютере с этим именем и что в домене ровно один DC.

### Передача scripts внутрь VM

Scripts обязаны запускаться локально внутри `DC01`: так работает их проверка имени компьютера, домена и одноузловой топологии. Для VirtualBox проще всего передать папку через **Shared Folder** (общая папка VirtualBox); это интеграция хоста и гостевой VM, а не подключение DC к корпоративной сети.

1. На VM установите Guest Additions: меню VirtualBox **Devices → Insert Guest Additions CD Image**, откройте появившийся CD в гостевой Windows, запустите `VBoxWindowsAdditions.exe` и перезагрузите VM.
2. Выключите VM. В VirtualBox откройте **Settings → Shared Folders**, нажмите значок добавления папки, укажите на основном ПК папку `scripts\adlab`, задайте имя `ira-adlab`, включите **Auto-mount** и **Make Permanent**, оставьте **Read-only** выключенным (нужно будет скопировать файлы в VM).
3. Запустите VM. В Проводнике гостевой Windows найдите `\\VBOXSVR\ira-adlab` (или подключённый сетевой диск `Z:`).
4. Скопируйте содержимое в `C:\IdentityRiskAnalyzer\scripts\adlab`. Удобно создать эту папку заранее. Все последующие команды запускаются из неё.

## Настройка изолированной сети между компьютером и DC01

Основной ПК запускает приложение, а VM предоставляет AD. Host-only сеть позволяет им общаться напрямую и изолирует DC от физической сети офиса/дома.

```text
┌────────────────────────────────┐
│ Основной Windows PC            │
│ Identity Risk Analyzer + SQLite│
│ Host-only адрес: 192.168.56.1  │
└───────────────┬────────────────┘
                │ только внутренняя VM-сеть
                │ TCP 389 (LDAP), позже 636 (LDAPS)
┌───────────────▼────────────────┐
│ VM: DC01                       │
│ Windows Server 2022            │
│ AD DS + DNS, adlab.test        │
│ тестовые users/groups          │
└────────────────────────────────┘
```

Пример ниже использует сеть `192.168.56.0/24`, адрес виртуального адаптера хоста `192.168.56.1` и статический адрес DC `192.168.56.10`. Если эта подсеть уже занята на компьютере, выберите другую свободную частную подсеть, затем последовательно замените адреса в инструкции. Скриптам нужны DNS-имя `dc01.adlab.test` и домен; IP не зашит в `LabConfig.ps1`.

### В VirtualBox

1. Откройте настройки сети VirtualBox Manager (в разных версиях: **Tools → Network** или **File → Tools → Network Manager**).
2. Создайте сеть **Host-only**. Если VirtualBox спрашивает параметры, задайте IPv4 сети хоста `192.168.56.1` и маску `255.255.255.0`.
3. Отключите DHCP для этой Host-only сети: адреса зададим вручную.
4. Откройте **DC01 → Settings → Network → Adapter 1**, включите адаптер, в **Attached to** выберите **Host-only Adapter** и созданный адаптер VirtualBox.
5. Проверьте, что Adapter 2 выключен. Не выбирайте **Bridged**, который подключил бы DC к той же физической сети, что и основной ПК.

### На Windows Server внутри DC01

1. Откройте **Server Manager → Local Server**, нажмите ссылку Ethernet. Либо нажмите `Win+R`, введите `ncpa.cpl`, нажмите Enter.
2. Нажмите правой кнопкой на сетевом адаптере VirtualBox → **Properties → Internet Protocol Version 4 (TCP/IPv4) → Properties**.
3. Выберите ручной IPv4 и введите: IP `192.168.56.10`, маска `255.255.255.0`, шлюз оставьте пустым, preferred DNS `192.168.56.10`. Нажмите OK.
4. После установки AD DS DNS на DC будет обслуживать зону `adlab.test`. DNS у самого DC должен указывать на него самого. Не задавайте в качестве DNS публичный DNS вроде `8.8.8.8`: публичный DNS не знает внутренние записи домена AD.

### На основном ПК — Host-only адаптер

1. Откройте `ncpa.cpl`, найдите **VirtualBox Host-Only Ethernet Adapter** (или имя, созданное VirtualBox), откройте его свойства IPv4.
2. Задайте IP `192.168.56.1`, маску `255.255.255.0`, шлюз оставьте пустым. Как DNS-сервер укажите `192.168.56.10` после того, как DC уже установлен и DNS работает.
3. Не изменяйте DNS или шлюз основного Wi-Fi/Ethernet адаптера. Host-only адаптер без шлюза не должен менять маршрут обычного интернет-трафика. Если после временного DNS на этом адаптере перестали разрешаться внешние имена, верните DNS Host-only адаптера в исходное состояние; для этого проекта важнее, чтобы `dc01.adlab.test` разрешался.

Почему DNS важен: AD регистрирует в DNS записи служб домена; приложение также подключается по имени `dc01.adlab.test`. Имя должно указывать на DC, а не на случайный IP. Для LDAPS имя ещё должно совпадать с именем в сертификате.

После создания домена на основном ПК проверьте:

```powershell
# ОСНОВНОЙ ПК, PowerShell
ipconfig
ping dc01.adlab.test
Resolve-DnsName dc01.adlab.test
Resolve-DnsName dc01.adlab.test -Server 192.168.56.10
Test-NetConnection dc01.adlab.test -Port 389
```

Ожидается DNS A-запись с адресом DC (например `192.168.56.10`) и `TcpTestSucceeded : True` для 389. `ping` может не отвечать, если ICMP закрыт firewall; это само по себе не означает, что LDAP недоступен. Проверка `Test-NetConnection` на 389 важнее.

## Что такое AD DS и что произойдёт при создании домена

`adlab.test` — выдуманное имя отдельного тестового корпоративного домена. Это не публичный интернет-сайт. `ADLAB` — короткое NetBIOS-имя, которое используется, например, в логине `ADLAB\svc_ira_scanner`. После установки AD DS сервер `DC01` станет Domain Controller и также будет DNS-сервером для домена.

`Base DN = DC=adlab,DC=test` — корневая запись домена: `DC` означает часть DNS-имени домена. Поиск от этого корня охватывает и лабораторную OU, и встроенные группы вроде `Domain Admins`. Если задать только `OU=HackathonLab,...`, приложение не увидит встроенную Domain Admins и не сможет показать полный тестовый privilege path.

**OU (Organizational Unit)** — контейнер-папка в каталоге. Scripts создают `OU=HackathonLab` и в ней папки для обычных пользователей, сервисных записей, тестовых групп и серверов. Все обычные lab objects создаются внутри этой отдельной OU.

## Разворачиваем тестовый Active Directory

### Общие правила PowerShell

Все команды в этом разделе выполняются **внутри DC01, в Windows PowerShell 5.1 от имени администратора**, из папки `C:\IdentityRiskAnalyzer\scripts\adlab`. Скрипты при запуске сами показывают предупреждение об изолированной лаборатории. Они рассчитаны на домен `adlab.test`, имя компьютера `DC01` и один контроллер домена.

Если Windows блокирует локальный скрипт из-за execution policy, не меняйте политику для всей машины. В повышенной PowerShell-сессии VM можно разрешить локальные scripts только для текущего процесса:

```powershell
# ТОЛЬКО ВНУТРИ DC01, PowerShell от администратора
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
Set-Location C:\IdentityRiskAnalyzer\scripts\adlab
```

Это разрешение исчезает после закрытия окна PowerShell. Не выполняйте `Set-ExecutionPolicy -Scope LocalMachine Unrestricted` и не обходите корпоративную политику на рабочей машине.

### 01 — установить AD DS и создать лес/домен

**Лес (forest)** — верхний уровень инфраструктуры Active Directory. В этой лаборатории будет один forest, один домен и один DC.

Перед этим шагом убедитесь, что имя Windows Server уже изменено на `DC01`, VM перезагружена, IP назначен, а снимок `A - чистый сервер, DC01` сделан.

```powershell
# ВНУТРИ DC01, PowerShell от администратора
Set-Location C:\IdentityRiskAnalyzer\scripts\adlab
.\01-Install-AdDsForest.ps1 -ConfirmLabInstall
```

Скрипт проверит права администратора, Windows Server, имя `DC01` и отсутствие уже установленной AD DS. Он добавит роль AD-Domain-Services с DNS и запустит создание `adlab.test` с NetBIOS `ADLAB`. Если DSRM password не передан параметром (в инструкции он не передаётся), PowerShell попросит ввести его через безопасный SecureString prompt. Введите сильный пароль и сохраните отдельно.

**DSRM** (Directory Services Restore Mode) — пароль для специального режима обслуживания/восстановления контроллера домена. Это не пароль scanner и не пароль тестовых пользователей. Не вводите пароль в команду, README или обычный текстовый файл.

После начала promotion VM перезагрузится. Продолжения «само собой» не будет. Войдите снова как `ADLAB\Administrator` (или `.Administrator`, если вход с коротким именем отображается в интерфейсе), используя пароль локального Administrator, заданный при установке Windows Server. DSRM password для обычного входа в домен не используется.

Нормальный результат — сервер загрузился, в Server Manager появилась роль AD DS, а команда ниже возвращает `adlab.test`:

```powershell
# ВНУТРИ DC01, PowerShell от администратора после перезагрузки
Get-ADDomain | Select-Object DNSRoot, NetBIOSName, DomainMode, DistinguishedName
Get-Service NTDS, DNS
```

Сделайте snapshot `B - AD DS установлен`. Если скрипт говорит, что имя не `DC01`, сначала переименуйте VM и перезагрузите. Если он говорит, что AD DS уже существует, **не запускайте установку леса снова**: перейдите к шагу 02.

### 02 — создать OU

**Что делает:** создаёт `OU=HackathonLab` и дочерние `Users`, `ServiceAccounts`, `Groups`, `Servers`. Это сортировка объектов, а также защитная граница scripts: объект с ожидаемым именем вне lab OU скрипт менять не будет.

```powershell
# ВНУТРИ DC01, PowerShell от администратора
Set-Location C:\IdentityRiskAnalyzer\scripts\adlab
.\02-Create-LabStructure.ps1
```

Скрипт не задаёт вопросов и не требует перезагрузки. При повторном запуске существующие OU пропускаются. Проверка:

```powershell
Get-ADOrganizationalUnit -SearchBase 'OU=HackathonLab,DC=adlab,DC=test' -SearchScope Subtree -Filter * |
    Select-Object Name, DistinguishedName
```

Ожидаются корневая OU и четыре дочерние. Ошибка «not a domain controller» означает, что команда запущена не на DC01, неверно установлен домен или AD PowerShell module не доступен.

### 03 — создать пользователей и тестовые группы

**Что делает:** создаёт 13 включённых пользовательских объектов (7 обычных и 6 сервисных) и три security-группы. Если появляются новые пользователи, скрипт запросит один SecureString пароль для них; пароль не печатается. Уже существующие объекты пропускаются. На этом этапе у объектов ещё не настроены сценарии риска — это делает шаг 04.

```powershell
# ВНУТРИ DC01, PowerShell от администратора
Set-Location C:\IdentityRiskAnalyzer\scripts\adlab
.\03-Create-LabAccounts.ps1
```

| Объект | Где создаётся | Для чего нужен |
| --- | --- | --- |
| `lab_clean_user` | Users | Чистая контрольная обычная учётная запись. |
| `lab_expired_user` | Users | На шаге 04 срок её учётной записи будет установлен на вчера. |
| `lab_pne_user` | Users | На шаге 04 включится Password Never Expires. |
| `lab_direct_admin` | Users | Будет напрямую включён в Backup Operators. |
| `lab_nested_admin` | Users | Проверка привилегий через цепочку вложенных групп. |
| `lab_multi_admin` | Users | Напрямую включается в две привилегированные группы. |
| `lab_locked_user` | Users | Будет реально заблокирован после заданных ошибочных попыток входа. |
| `svc_sql` | ServiceAccounts | SPN службы SQL и Password Never Expires; демонстрация service-account риска. |
| `svc_unconstrained` | ServiceAccounts | SPN и флаг Unconstrained Delegation. |
| `svc_constrained` | ServiceAccounts | Собственный SPN плюс заданная цель Constrained Delegation. |
| `svc_protocol_transition` | ServiceAccounts | Цель delegation плюс Protocol Transition. |
| `svc_rbcd_source` | ServiceAccounts | Источник, которому лаборатория разрешит RBCD на целевом объекте. |
| `svc_rbcd_target` | ServiceAccounts | Целевой объект с настроенной RBCD. |
| `DemoHelpDesk` | Groups | Первая группа в nested path. |
| `DemoITAdmins` | Groups | Вложенная группа, которая для теста входит в Domain Admins. |
| `DemoGmsaHosts` | Groups | Компьютерная группа, которой разрешён managed password gMSA. |
| `gmsa_demo` | ServiceAccounts | Создаётся настоящим AD cmdlet на шаге 04; это gMSA, а не обычный user. |
| `svc_ira_scanner` | ServiceAccounts | Создаётся отдельно шагом 05 и используется приложением для чтения AD. |

Скрипт не задаёт вопросов и не требует перезагрузки. При создании объектов появится `[OK]`, уже имеющиеся в правильной OU будут отмечены `[SKIP]`. Если скрипт запросил пароль, введите сильный пароль для новых тестовых объектов. Проверьте папки:

```powershell
Get-ADUser -SearchBase 'OU=HackathonLab,DC=adlab,DC=test' -SearchScope Subtree -Filter * |
    Select-Object SamAccountName, Enabled, DistinguishedName
Get-ADGroup -SearchBase 'OU=Groups,OU=HackathonLab,DC=adlab,DC=test' -Filter * |
    Select-Object Name, GroupCategory, GroupScope
```

### 04 — настроить сценарии риска

Этот шаг намеренно меняет AD внутри лаборатории. Перед запуском сверьтесь с большим предупреждением в начале README. Команда требует явного `-ConfirmLabChanges`.

```powershell
# ТОЛЬКО ВНУТРИ ИЗОЛИРОВАННОГО DC01
Set-Location C:\IdentityRiskAnalyzer\scripts\adlab
.\04-Configure-RiskScenarios.ps1 -ConfirmLabChanges
```

Скрипт выставит истечение `lab_expired_user` на вчера, включит PNE у `lab_pne_user` и `svc_sql`, безопасно добавит проверенные на уникальность SPN, настроит direct/nested memberships и delegation. Он также создаёт gMSA, lab-only fine-grained password policy и делает реальные ошибки LDAP-входа для блокировки `lab_locked_user`.

gMSA требует KDS root key и функциональный уровень домена Windows Server 2012 или новее. В этой лаборатории один DC; только если KDS key отсутствует, скрипт использует тестовый приём `Add-KdsRootKey -EffectiveTime` со временем 10 часов назад. Это необходимо для одноузлового теста gMSA и **не является production-рекомендацией**. Скрипт не удаляет ключ. `DemoGmsaHosts` позволяет DC получить managed password; устанавливать gMSA на Windows-службу не нужно.

Для блокировки скрипт создаёт `HackathonLab-LockoutPSO`: порог 3 ошибки, длительность 30 минут, окно подсчёта 10 минут; назначает политику только `lab_locked_user`, делает до трёх намеренно неверных LDAP-аутентификаций и проверяет фактический `LockedOut` и computed UAC. Он не подделывает `lockoutTime`. Не запускайте эти попытки на иных аккаунтах.

Ожидайте сообщения `[OK]`, `[SKIP]` или `[UPDATE]`. Скрипт не требует перезагрузки и не задаёт дополнительных вопросов; успешное завершение заканчивается подсказкой выполнить 06. Если gMSA prerequisites не соблюдены или effective lockout не подтверждён, скрипт завершится ошибкой; исправьте именно prerequisite, не подменяйте результат вручную.

### 05 — создать scanner account

```powershell
# ВНУТРИ DC01, PowerShell от администратора
Set-Location C:\IdentityRiskAnalyzer\scripts\adlab
.\05-Create-ScannerAccount.ps1
```

Если scanner ещё нет, скрипт попросит ввести **отдельный** SecureString пароль. Это пароль для User Secrets на основном ПК. Если scanner уже существует в нужной OU, скрипт оставит его пароль как есть, включит аккаунт и проверит, что `PasswordNeverExpires` выключен. Пароль можно сбросить, передав параметр `-ScannerPassword` как SecureString из PowerShell; для новичка проще оставить существующий пароль и не менять его. Скрипт не требует перезагрузки; в конце ожидается сообщение, что scanner включён и не имеет административных memberships.

`svc_ira_scanner` — обычный Domain User внутри `OU=ServiceAccounts`. Скрипт проверяет, что он не состоит в перечисленных административных группах, и специально **не** делает его Domain Admin. Обычного чтения каталога достаточно для текущих LDAP collectors. Не давайте ему Domain Admin, чтобы «починить» ошибку чтения: сначала проверьте Base DN, DNS и корректность имени/пароля.

### 06 — прочитать и проверить реальные свойства AD

```powershell
# ВНУТРИ DC01, PowerShell
Set-Location C:\IdentityRiskAnalyzer\scripts\adlab
.\06-Verify-Lab.ps1
```

Скрипт ничего не исправляет: он читает `Get-ADUser`, `Get-ADGroup`, `Get-ADServiceAccount`, членство, UAC, SPN, delegation-атрибуты и свойства PSO. Сейчас он проверяет **14 сценариев**, включая scanner и gMSA. Ожидается таблица, где у каждой строки `Status = OK`, затем сообщение о количестве проверенных сценариев. Перезагрузка не требуется. Любой `FAIL` делает завершение ненулевым — используйте текст `Details`, проверьте предыдущие шаги и запустите 06 повторно.

### 07 — показать несекретные параметры приложения

```powershell
# ВНУТРИ DC01, PowerShell
Set-Location C:\IdentityRiskAnalyzer\scripts\adlab
.\07-Print-AppConfiguration.ps1
```

Это только вывод, он не меняет AD, ничего не настраивает, не задаёт вопросов и не требует перезагрузки. Для основного сценария в выводе ожидаются `dc01.adlab.test`, `389`, `false`, `DC=adlab,DC=test`, `ADLAB\svc_ira_scanner`; вместо пароля напечатан placeholder. Пароль вводится отдельно в User Secrets на ПК.

После 06 рекомендуется сделать snapshot `C - AD и risk scenarios готовы`: выделите `DC01` в VirtualBox → **Machine → Take Snapshot**. Если вы собираетесь показывать приложение, не удаляйте lab objects.

## Какой риск создаёт каждый сценарий

Список ниже сверён с `scripts/adlab/EXPECTED_FINDINGS.md` и `ExpectedFindings.psd1`. Проверяйте присутствие указанных RuleId, а не точное равенство всех findings: у объекта могут быть дополнительные валидные находки. Не требуйте конкретного общего AD Security Score.

| Объект | Что настроено | Минимально ожидаемые RuleId |
| --- | --- | --- |
| `lab_clean_user` | Включённый обычный пользователь без добавленных lab privilege, SPN, delegation и PNE. | Нет специальных для лаборатории обязательных RuleId. |
| `lab_expired_user` | Дата завершения аккаунта установлена на вчера. | `IRA-ACCOUNT-002` |
| `lab_pne_user` | Установлен признак Password Never Expires. | `IRA-PASSWORD-001` |
| `svc_sql` | Уникальный `MSSQLSvc/sql01.adlab.test:1433` SPN и PNE. | `IRA-PASSWORD-001`, `IRA-SERVICE-001` |
| `lab_direct_admin` | Прямое членство в Backup Operators. | `IRA-PRIV-001` |
| `lab_nested_admin` | Путь через `DemoHelpDesk`, `DemoITAdmins` в Domain Admins. | `IRA-PRIV-002` |
| `lab_multi_admin` | Прямое членство в Backup Operators и Server Operators. | `IRA-PRIV-001` (для каждой группы), `IRA-PRIV-003` |
| `svc_unconstrained` | SPN аккаунта и TRUSTED_FOR_DELEGATION. | `IRA-DELEGATION-001` |
| `svc_constrained` | Свой SPN и цель `HTTP/app01.adlab.test`. | `IRA-DELEGATION-002` |
| `svc_protocol_transition` | Цель `HTTP/app01.adlab.test` и TRUSTED_TO_AUTH_FOR_DELEGATION. | `IRA-DELEGATION-003` |
| `svc_rbcd_target` | RBCD разрешает delegation от `svc_rbcd_source`. | `IRA-DELEGATION-004` |
| `lab_locked_user` | Реально заблокирован после неуспешных входов, проверен computed UAC. | `IRA-ACCOUNT-003` |
| `gmsa_demo` | Настоящий объект `msDS-GroupManagedServiceAccount`. | Finding не обязателен; снимок должен содержать `IsServiceAccount = true`. |

Nested path — важное доказательство: пользователь может получить права администратора не будучи прямым участником Domain Admins. Его членство проходит через вложенные группы. Приложение должно показать:

```text
lab_nested_admin
→ DemoHelpDesk
→ DemoITAdmins
→ Domain Admins
```

В этой цепочке глубина равна 3 (три group memberships от user к target). Это показывает не только «пользователь привилегированный», но и объясняет путь.

### Почему некоторые findings не появятся в свежей лаборатории

Следующие правила существуют, но соответствующую историю нельзя реалистично и детерминированно создать штатными поддерживаемыми административными командами в свежем домене:

* `IRA-ACCOUNT-001` — старый `lastLogonTimestamp`: приложение использует настоящий реплицируемый timestamp; в свежем AD нет поддерживаемого способа просто задать выдуманную прошлую дату.
* `IRA-PASSWORD-002` — произвольный старый `pwdLastSet`: AD устанавливает его при смене пароля; скрипт не подделывает дату.
* `IRA-SPN-001` — современный AD проверяет уникальность SPN и может отклонить duplicate; лаборатория не отключает forest-wide uniqueness.
* `IRA-AD-001` — SIDHistory не подделывается; для него нужна легитимная миграционная история.

Это не недостаток тестовых scripts и не повод ослаблять risk rule. Эти правила покрываются автоматическими .NET tests.

## Подключаем приложение к DC01 по LDAP 389

### Что такое User Secrets

User Secrets — локальное хранилище секретной конфигурации .NET для разработки. Значения не записываются в `appsettings.json` и не попадают в Git, но это не production vault и не замена защищённому хранилищу в production. В Web-проекте уже настроен `UserSecretsId`, поэтому `dotnet user-secrets init` повторно не нужен.

### Сохранить настройки на основном ПК

Откройте PowerShell на **основном ПК** и перейдите из корня repository в Web-проект:

```powershell
# ОСНОВНОЙ ПК, из корня repository
Set-Location .\src\IdentityRiskAnalyzer.Web
```

Настройки LDAP 389 для лаборатории:

```text
Server   = dc01.adlab.test
Port     = 389
UseSsl   = false
BaseDn   = DC=adlab,DC=test
Username = ADLAB\svc_ira_scanner
Password = пароль, введённый в шаге 05 (не вставлять в README или appsettings.json)
```

Выполните copy-paste блок. Он хранит несекретные параметры, а пароль запрашивает скрытым вводом PowerShell:

```powershell
# ОСНОВНОЙ ПК, каталог src\IdentityRiskAnalyzer.Web
dotnet user-secrets set "ActiveDirectory:Server" "dc01.adlab.test"
dotnet user-secrets set "ActiveDirectory:Port" "389"
dotnet user-secrets set "ActiveDirectory:UseSsl" "false"
dotnet user-secrets set "ActiveDirectory:BaseDn" "DC=adlab,DC=test"
dotnet user-secrets set "ActiveDirectory:Username" "ADLAB\svc_ira_scanner"

$securePassword = Read-Host "Введите пароль ADLAB\svc_ira_scanner" -AsSecureString
$passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
try {
    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
    dotnet user-secrets set "ActiveDirectory:Password" $plainPassword
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    Remove-Variable plainPassword, securePassword -ErrorAction SilentlyContinue
}

dotnet user-secrets list
```

Значения `Server`, `Port`, `UseSsl`, `BaseDn`, `Username` и `Password` должны соответствовать ключам `ActiveDirectoryOptions`. `dotnet user-secrets list` покажет секреты в терминале, поэтому убедитесь, что никто не смотрит на экран; не копируйте его вывод в issue или чат. Команда `set` получает значение password как кратковременный аргумент процесса .NET; локальный пользователь с правом наблюдать процессы теоретически может увидеть его в момент выполнения. Для защищённой общей/production среды используйте отдельное управляемое secret storage.

Не храните scanner password в git, `appsettings.json`, CSV, скриншотах или общем README. В текущем `appsettings.json` уже указаны только безопасные lab defaults (server, port, SSL, Base DN); Username и Password там отсутствуют.

Проверить DNS и порт до запуска приложения:

```powershell
# ОСНОВНОЙ ПК
Resolve-DnsName dc01.adlab.test
Test-NetConnection dc01.adlab.test -Port 389
```

### Запустить Web-приложение

Оставаясь в `src\IdentityRiskAnalyzer.Web`, выполните:

```powershell
# ОСНОВНОЙ ПК, каталог src\IdentityRiskAnalyzer.Web
dotnet run
```

При первом запуске .NET применяет существующие EF migrations к SQLite. Дождитесь строки `Now listening on: ...` и откройте именно этот адрес в браузере. В текущем `launchSettings.json` профили задают HTTP `http://localhost:5207` и HTTPS `https://localhost:7000`; фактический адрес из консоли является главным. Для явного HTTP-профиля можно выполнить `dotnet run --launch-profile http`.

### Проверить Test Connection

1. В браузере откройте `/ActiveDirectory`, например `http://localhost:5207/ActiveDirectory`.
2. Проверьте отображённые Server, Port, Protocol, Base DN, timeout и `Credentials configured: Yes`. Пароля на странице быть не должно.
3. Нажмите **Test Connection**. Это POST-действие с antiforgery protection.
4. Успешный результат означает, что приложение смогло обратиться к DC, выполнить Negotiate bind под scanner credentials и сделать небольшой запрос к настроенному Base DN.

**Test Connection ещё не выполняет scan и не загружает всех пользователей.** Он проверяет связь, аутентификацию и доступность Base DN. После успеха откройте Users и Groups.

### Проверить пользователей и группы

Откройте `/ActiveDirectory/Users`. Страница выполняет диагностическую текущую LDAP-загрузку, а не читает исторический ScanRun. Показывает ограниченное число строк (первые 100), например `lab_clean_user`, `lab_nested_admin`, `svc_sql`, и сервисную классификацию. Пароли пользователей и хеши приложение не запрашивает.

Откройте `/ActiveDirectory/Groups`. Проверьте `DemoHelpDesk`, `DemoITAdmins`, а также привилегированные built-in groups, если они входят в Base DN. Эта страница показывает direct member count; она сама не доказывает весь вложенный путь — его проверяйте после ScanRun в деталях account.

Если объекты не появились, сначала проверьте DNS, 389, User Secrets и Base DN. Base DN должен быть корнем всего домена `DC=adlab,DC=test`, а не только OU. На DC выполните `06-Verify-Lab.ps1` и убедитесь, что lab objects реально существуют.

## Запускаем первый полный анализ

1. Откройте `/Scans` в приложении.
2. Нажмите **Start Scan**. Кнопка отправляет POST-запрос; страница ждёт окончания pipeline и затем открывает детали scan. В MVP одновременно допускается один scan на экземпляр приложения.
3. Подождите окончания LDAP collection и анализа. Не закрывайте окно приложения и не перезапускайте его, пока запрос выполняется.
4. На странице деталей проверьте Status, Server, Base DN, Objects, Findings, Errors и AD Security Score.
5. После завершения перейдите на `/` — это Dashboard последнего успешно завершённого scan.

Статусы:

| Статус | Простое значение |
| --- | --- |
| `Running` | Scan ещё выполняется. |
| `Completed` | Завершился без зарегистрированных recoverable errors. |
| `CompletedWithErrors` | Основной scan и snapshot завершились, но часть объектов/необязательных анализаторов дала ошибки. Проверьте ErrorsCount и журналы приложения. Это не обязательно полный провал. |
| `Failed` | Фатально не удалось завершить сбор или сохранить snapshot. Проверьте безопасное сообщение на странице и приложение logs. |
| `Cancelled` | Запрос был отменён до завершения. |

Если scan `Completed` или `CompletedWithErrors`, проверяйте Dashboard и детали. Если `Failed`, сначала пройдите раздел [Диагностика ошибок](#диагностика-ошибок). Приложение сохранит попытку `ScanRun` в SQLite, если удалось создать её до ошибки.

## Проверяем результаты по аккаунтам

Сверяйте именно свежий завершённый scan. Откройте Dashboard и выберите объект из Top Risky Accounts или список сохранённых аккаунтов; historical details доступны по маршруту `/Scans/{scanId}/Objects/{objectGuid}` и показывают результаты выбранного снимка.

### `lab_expired_user`

Откройте детали объекта. В Findings должна быть `IRA-ACCOUNT-002` с evidence, где дата истечения раньше времени scan. Причина: учётная запись включена, но её настроенный срок уже прошёл.

### `lab_pne_user`

Ожидается `IRA-PASSWORD-001`. Evidence ссылается на флаг `DONT_EXPIRE_PASSWORD`. Это не означает, что пароль плохой; это означает, что AD не требует истечения этого пароля.

### `svc_sql`

Проверьте `IsServiceAccount = true`, SPN `MSSQLSvc/sql01.adlab.test:1433` в диагностике, и findings `IRA-PASSWORD-001` плюс `IRA-SERVICE-001`. У `IRA-SERVICE-001` смысл в сочетании классификации service account с паролем, который не истекает.

### `lab_direct_admin`

Ожидается `IRA-PRIV-001`; Evidence должен называть Backup Operators и указывать `Direct`, глубину 1 и путь от аккаунта к группе.

### `lab_nested_admin` — главная демонстрация

Ожидается `IRA-PRIV-002` и читаемый полный путь:

```text
lab_nested_admin
→ DemoHelpDesk
→ DemoITAdmins
→ Domain Admins
```

Путь показывает, что полномочия могут прийти через nested membership. `lab_nested_admin` напрямую не добавляли в Domain Admins: в Domain Admins входит `DemoITAdmins`, та содержит `DemoHelpDesk`, а первая группа содержит пользователя. Это наглядно объясняет, почему важно анализировать вложенные группы, а не только прямой список.

### `lab_multi_admin`

Ожидается как минимум `IRA-PRIV-001` для каждого direct privileged target и `IRA-PRIV-003` за две разные административные роли. Посмотрите все привилегированные memberships, а не только одну строку finding.

### Service accounts и delegation

* `svc_unconstrained`: `IRA-DELEGATION-001`; в evidence должен быть факт TRUSTED_FOR_DELEGATION.
* `svc_constrained`: `IRA-DELEGATION-002`; target — `HTTP/app01.adlab.test`.
* `svc_protocol_transition`: `IRA-DELEGATION-003`; target и Protocol Transition. Правило более специфично, не ждите дополнительный constrained finding по той же конфигурации.
* `svc_rbcd_target`: `IRA-DELEGATION-004`; attribute RBCD настроен. MVP отмечает наличие, но не разбирает ACL security descriptor.
* `lab_locked_user`: `IRA-ACCOUNT-003` только если аккаунт всё ещё locked на время scan. Его lockout истекает через 30 минут.
* `gmsa_demo`: на details должен быть `IsServiceAccount = true`; обязательный risk finding для него не задан.

## Dashboard: как читать показатели

Dashboard route — `/` или `/Dashboard`. Он показывает последний `Completed` или `CompletedWithErrors` scan. Если последний запуск был `Failed`, основной Dashboard продолжает показывать последний успешный снимок и может отдельно предупреждать о последней неудачной попытке. Если завершённых scan ещё нет, появится empty state с предложением начать scan; demo numbers не подставляются.

| Показатель | Что означает |
| --- | --- |
| **AD Security Score** | Общая сводная оценка по объектам этого scan. **100 — лучше, 0 — хуже**. При нуле проанализированных объектов значение пустое/null, а не 100. |
| **Critical / High / Medium / Low Findings** | Количество сохранённых findings с severity, установленной для конкретного правила. Одна учётная запись может иметь несколько findings. |
| **Analysed Accounts / Objects** | Число объектов, реально прошедших risk evaluation. Groups не смешиваются с этим числом. |
| **Service Accounts** | Число объектов снимка, классифицированных как сервисные учётные записи. |
| **Privileged Accounts** | Число объектов снимка, имеющих membership path до настроенной привилегированной группы. |
| **Stale Accounts** | Число разных объектов, для которых сохранён finding `IRA-ACCOUNT-001`. |
| **Top Risky Accounts** | Несколько объектов с наибольшим сохранённым Object Risk Score. Нажмите на имя для исторических деталей. |
| **Risk Categories** | Группировка сохранённых findings по категориям риска. |
| **Score History** | Оценки последних сохранённых scans; открывает динамику между снимками, не пересканируя AD. |

Важно различать две шкалы:

* **Object Risk Score**: `0` означает, что у объекта нет набранных риск-баллов; `100` — высокий суммарный риск. Он складывает баллы уникальных findings объекта и ограничивается диапазоном 0–100.
* **AD Security Score**: `100` — лучший агрегированный результат; он вычисляется как `100 - средний Object Risk Score` по анализированным объектам, округляется до ближайшего целого (половины от нуля вверх) и ограничивается 0–100.

Уровень объекта задаётся порогами из текущего `appsettings.json`: Low — score `< 25`, Medium — `25–49`, High — `50–74`, Critical — `75–100`. Severity отдельного finding — другая характеристика: например finding может быть Critical, тогда как совокупный object score остаётся ниже 75.

## Account Details и исторические снимки

Чтобы открыть details, нажмите объект в Top Risky Accounts (или соответствующую ссылку в сохранённых результатах). Страница отвечает на вопрос, почему объект получил свою оценку:

* **Risk Score / Risk Level** — итоговые Object Risk Score и уровень риска из сохранённого snapshot.
* **Risk Score Breakdown** — сумма баллов сохранённых findings. Отображает вклад правил, не запускает их снова.
* **Findings** — сработавшие правила с RuleId, severity, title, description и points.
* **Evidence** — какие именно сохранённые атрибуты/путь послужили основанием. Для nested privilege тут показывается цепочка групп.
* **Recommendation** — предложение для ручной проверки/процесса организации. Приложение его автоматически не применяет.
* **Privileged Memberships** — целевые privileged groups с отметкой Direct/Nested, глубиной и полной цепочкой.
* **Delegation** — тип Kerberos delegation, targets и evidence; RBCD ACL детально не анализируется.
* **Group Memberships** — сохранённые прямые и вложенные связи, с постраничным просмотром.

Details для `/Scans/{scanId}/Objects/{objectGuid}` читаются из SQLite и не обращаются к LDAP. Если AD изменился после scan, старая карточка остаётся историческим состоянием на момент этого scan.

### Проверка истории Scan A / Scan B

Этот тест демонстрирует, что сканы являются отдельными историческими снимками. Выполняйте изменение только на изолированном `DC01`.

1. Убедитесь, что `DemoITAdmins` входит в Domain Admins:

```powershell
# ВНУТРИ DC01, PowerShell от администратора
$domain = Get-ADDomain
$domainAdmins = Get-ADGroup -Identity ("{0}-512" -f $domain.DomainSID.Value)
$itAdmins = Get-ADGroup -Identity 'DemoITAdmins'
Get-ADGroupMember -Identity $domainAdmins | Select-Object Name, DistinguishedName
```

2. На основном ПК запустите scan A. Откройте исторические детали `lab_nested_admin`: ожидается `IRA-PRIV-002` и полный путь до Domain Admins.
3. Удалите только вложенную группу DemoITAdmins из Domain Admins в лаборатории:

```powershell
# ТОЛЬКО ВНУТРИ DC01, PowerShell от администратора; проверьте переменные перед Enter
$domain = Get-ADDomain
$domainAdmins = Get-ADGroup -Identity ("{0}-512" -f $domain.DomainSID.Value)
$itAdmins = Get-ADGroup -Identity 'DemoITAdmins'
Remove-ADGroupMember -Identity $domainAdmins -Members $itAdmins -Confirm:$true
```

Команда спрашивает подтверждение. На сервере должна отображаться группа с именем `DemoITAdmins`, а домен — `adlab.test`. Если сомневаетесь, введите `N` и остановитесь.

4. Запустите scan B на основном ПК. В новых данных путь до Domain Admins и соответствующий nested finding должны исчезнуть/измениться.
5. Откройте scan A снова: его старый snapshot и прежний path должны сохраниться. На Dashboard Score History будут оба завершённых scan.
6. Чтобы вернуть исходный тестовый путь для следующей демонстрации, снова добавьте группу:

```powershell
# ТОЛЬКО ВНУТРИ DC01, PowerShell от администратора
$domain = Get-ADDomain
$domainAdmins = Get-ADGroup -Identity ("{0}-512" -f $domain.DomainSID.Value)
$itAdmins = Get-ADGroup -Identity 'DemoITAdmins'
Add-ADGroupMember -Identity $domainAdmins -Members $itAdmins
```

Запустите новый scan, чтобы Dashboard снова отразил восстановленный путь. Предыдущие scans автоматически не меняются.

## CSV Export

Откройте `/Scans/{id}` для завершённого scan. На странице есть ссылки **Accounts CSV** и **Findings CSV**; маршруты:

```text
GET /Scans/{scanId}/Export/Accounts
GET /Scans/{scanId}/Export/Findings
```

Accounts CSV — одна строка на сохранённый объект: имя, тип, статус/атрибуты и итоговые score/level, плюс число findings. Основные заголовки: `ObjectGuid`, `ObjectType`, `SamAccountName`, `DisplayName`, `UserPrincipalName`, `DistinguishedName`, `Sid`, `Enabled`, `Locked`, `AccountExpired`, `IsServiceAccount`, `IsPrivileged`, `LastKnownActivityUtc`, `PasswordLastSetUtc`, `PasswordNeverExpires`, `RiskScore`, `RiskLevel`, `FindingsCount`. Findings CSV — одна строка на сохранённую находку; заголовки включают `ObjectName`, `RuleId`, `Category`, `Severity`, `RiskPoints`, `Title`, `Description`, `Evidence`, `Recommendation`, `ObjectRiskScore`, `ObjectRiskLevel`. Оба файла включают `ScanId` и статус scan. CSV скачивается из SQLite и повторно не обращается к AD.

Файл использует `;` как разделитель, UTF-8 с BOM и CRLF; его можно открыть Excel или LibreOffice. Кириллица должна отображаться корректно. Проверьте наличие `lab_nested_admin`, `svc_sql`, RuleId и сохранённого evidence. Экспорт доступен только для `Completed` и `CompletedWithErrors`; для `Failed`, `Running`, `Cancelled` или неизвестного ID сервер ответит 404, а не создаст пустой отчёт.

## SQLite: где лежит история

В `src/IdentityRiskAnalyzer.Web/appsettings.json` connection string сейчас задан так:

```text
Data Source=identity-risk-analyzer.db
```

Это относительный путь. Если Web запущен стандартной командой `dotnet run` из папки `src\IdentityRiskAnalyzer.Web`, файл будет создан там же:

```text
src\IdentityRiskAnalyzer.Web\identity-risk-analyzer.db
```

База содержит таблицы ScanRun, снимки AD объектов, GroupMembership, DelegationRecord и RiskFinding. Приложение применяет EF migrations при старте. Удалять файл не нужно и нежелательно, если важна история. Dashboard/history читают его. Не отправляйте эту базу наружу без проверки: она может содержать внутренние имена, DN и сведения о рисках, хотя пароли в ней не хранятся.

## Что означают основные находки

| Находка | Человеческое объяснение |
| --- | --- |
| Истёкшая учётная запись | Настроенная дата окончания уже прошла. Проверьте, нужна ли ещё запись и правильно ли задан срок. |
| Password Never Expires | Для пароля включено «никогда не истекает». Риск зависит от назначения аккаунта и компенсирующих мер. |
| Service Account | Учётная запись используется приложением/службой. Приложение распознаёт её по собранным признакам (например, SPN или классификатору); сама классификация не означает проблему. |
| SPN | Идентификатор службы, зарегистрированный на аккаунте. Он нужен для Kerberos; дубли между объектами могут указывать на проблему конфигурации. |
| Direct privilege | Пользователь непосредственно включён в privileged group. Путь имеет глубину 1. |
| Nested privilege | Права приходят через вложенные группы. Важен полный path, а не только прямое членство. |
| Multiple administrative roles | Пользователь достигает двух или более разных настроенных privileged groups. Это повышает объём доступных полномочий. |
| Unconstrained Delegation | Службе разрешена широкая Kerberos delegation без ограничения конкретными целевыми службами; конфигурация требует внимательной проверки. |
| Constrained Delegation | Для delegation явно задан список target services, но нужно проверить необходимость и точность этих targets. |
| Protocol Transition | Сочетание constrained targets и флага, разрешающего переход от не-Kerberos аутентификации. Это более специфичная конфигурация. |
| RBCD | Resource-Based Constrained Delegation задана на целевом объекте. MVP обнаруживает наличие атрибута, но не вычисляет ACL и не определяет, кто именно имеет разрешение. |
| Locked account | AD сейчас сообщает о блокировке. Это может быть следствием ошибочных входов; выясните причину до ручного восстановления. |
| SIDHistory | У объекта есть старые SID, обычно связанные с миграцией. Нужно подтвердить законность происхождения; само наличие не доказывает злоупотребление. |
| Duplicate SPN | Один SPN назначен разным объектам. Сценарий не создаётся в стандартной свежей AD lab. |
| Possible Password Spray | Эвристика по журналу событий: много неуспешных входов с одного источника по нескольким разным именам. Это сигнал для расследования, не доказательство атаки. |
| Possible Brute Force | Эвристика по журналу событий: много неуспешных входов по одному имени за короткое окно. Это также не доказательство компрометации. |

## Необязательная глава: LDAPS 636

Сначала добейтесь успешного LDAP 389 и успешного сохранённого scan. Только после этого переходите к LDAPS. **LDAPS — это LDAP поверх TLS-сертификата**, поэтому кроме соединения важны доверие к CA, срок сертификата и совпадение DNS-имени.

* **CA (Certification Authority)** — сервер/служба, выпускающая сертификаты. Корневой сертификат CA подтверждает, что сертификат DC выдан доверенной стороной.
* **Сертификат DC** — сертификат сервера. Он должен содержать закрытый ключ, действующий срок, назначение Server Authentication и DNS-имя `dc01.adlab.test` в CN/SAN.
* **SAN** — список имён, для которых выпущен сертификат. Клиент сверяет именно hostname подключения с сертификатом.
* **Trusted Root** — системное хранилище доверенных корневых CA на машине приложения. Переносить туда можно только публичный `.cer`; никогда не переносите private key или `.pfx`.

### Установить лабораторную CA и сертификат DC

На изолированной VM запустите в повышенной PowerShell-сессии из папки scripts:

```powershell
# ТОЛЬКО ВНУТРИ DC01, PowerShell от администратора
Set-Location C:\IdentityRiskAnalyzer\scripts\adlab
.\08-Install-LabCertificateAuthority.ps1 -ConfirmLabCaInstall
```

Script добавляет роль AD CS и создаёт Enterprise Root CA `ADLAB-Lab-Root-CA`, если CA ещё нет. Он откажется заменять неизвестную CA-конфигурацию. Закрытый ключ остаётся на DC. Для production CA архитектура должна быть иной; это только одноузловой test lab.

Затем запросите сертификат DC:

```powershell
# ТОЛЬКО ВНУТРИ DC01, PowerShell от администратора
.\09-Configure-DcLdapsCertificate.ps1
```

Script публикует шаблон `DomainControllerAuthentication`, если нужно, и запрашивает машинный сертификат через `certreq -enroll -machine`. Он проверяет hostname, Server Authentication EKU, private key, срок и цепочку. Он не перезагружает DC автоматически. Если LDAP на 636 не подхватил новый сертификат, вручную перезагрузите `DC01`, затем продолжите.

### Проверить 636 на DC

Внутри DC01 выполните:

```powershell
# ВНУТРИ DC01
Set-Location C:\IdentityRiskAnalyzer\scripts\adlab
$scanner = Get-Credential 'ADLAB\svc_ira_scanner'
.\10-Verify-Ldaps.ps1 -Credential $scanner
```

Введите scanner password в стандартном secure credential window. Таблица проверяет DNS, TCP 636, сертификат и настоящий LDAPS Negotiate bind + Base DN query. Без `-Credential` bind будет `NOT TESTED`. Завершение с `FAIL` значит, что LDAPS ещё не подтверждён.

Дополнительная проверка на основном ПК:

```powershell
# ОСНОВНОЙ ПК
Resolve-DnsName dc01.adlab.test
Test-NetConnection dc01.adlab.test -Port 636
```

`TcpTestSucceeded = True` подтверждает только сетевой порт, но не доверие TLS.

Для ручного теста на Windows Server откройте `ldp.exe` → **Connection → Connect**, укажите `dc01.adlab.test`, порт `636`, установите **SSL** и нажмите OK. При успехе LDP показывает RootDSE.

### Доверить публичный root CA на основном ПК

На DC экспортируйте только открытый сертификат CA:

```powershell
# ВНУТРИ DC01, PowerShell
New-Item -ItemType Directory -Force C:\Temp | Out-Null
certutil -ca.cert C:\Temp\adlab-root-ca.cer
```

Перенесите `adlab-root-ca.cer` на основной ПК через Shared Folder. Не экспортируйте PFX и не копируйте закрытый ключ CA. На основном ПК откройте `Win+R` → `certlm.msc` (Certificates — Local Computer), правой кнопкой по **Trusted Root Certification Authorities → Certificates** → **All Tasks → Import**, выберите `adlab-root-ca.cer`, завершите мастер. Либо в повышенном PowerShell:

```powershell
# ОСНОВНОЙ ПК, PowerShell от администратора, из папки с публичным .cer
Import-Certificate -FilePath .\adlab-root-ca.cer -CertStoreLocation Cert:\LocalMachine\Root
```

После этого приложение должно доверять корню, но всё ещё проверяет имя и срок сертификата.

### Переключить приложение на LDAPS

В папке Web-проекта на основном ПК измените только три настройки:

```powershell
# ОСНОВНОЙ ПК, каталог src\IdentityRiskAnalyzer.Web
dotnet user-secrets set "ActiveDirectory:Server" "dc01.adlab.test"
dotnet user-secrets set "ActiveDirectory:Port" "636"
dotnet user-secrets set "ActiveDirectory:UseSsl" "true"
```

Остановите Web-приложение и запустите снова. Затем повторите `/ActiveDirectory` → **Test Connection**, Users, Groups и полный scan. `UseSsl=true` — прямой LDAPS; StartTLS здесь не настраивается.

Проверка отказа сертификата (необязательно): приложение должно использовать DNS hostname сертификата. Код отклоняет IP для LDAPS раньше сетевого подключения. В **изолированной лаборатории** можно временно создать alias `dc01-alias.adlab.test`, которого нет в SAN сертификата, направив его на IP DC. Внутри DC01 выполните:

```powershell
# ТОЛЬКО ВНУТРИ DC01, PowerShell от администратора; alias должен отсутствовать
Get-DnsServerResourceRecord -ZoneName 'adlab.test' -Name 'dc01-alias' -ErrorAction SilentlyContinue
Add-DnsServerResourceRecordA -ZoneName 'adlab.test' -Name 'dc01-alias' -IPv4Address '192.168.56.10'
```

Убедитесь, что `Resolve-DnsName dc01-alias.adlab.test` на основном ПК возвращает IP DC. На основном ПК временно задайте `ActiveDirectory:Server=dc01-alias.adlab.test` в User Secrets и нажмите Test Connection: ожидание — TLS name failure. Сразу верните `dc01.adlab.test` и удалите только созданную alias-запись на DC:

```powershell
# ОСНОВНОЙ ПК, каталог src\IdentityRiskAnalyzer.Web
dotnet user-secrets set "ActiveDirectory:Server" "dc01.adlab.test"
```

```powershell
# ТОЛЬКО ВНУТРИ DC01, PowerShell от администратора
Remove-DnsServerResourceRecord -ZoneName 'adlab.test' -Name 'dc01-alias' -RRType 'A' -RecordData '192.168.56.10' -Force
```

Если alias существовал до проверки, не добавляйте и не удаляйте его. Не отключайте проверку сертификата и не используйте callback «доверять любому сертификату».

## Необязательная глава: Security Event Log

Главный MVP не зависит от Windows Security Event Log. Секция `SecurityEventLog:Enabled` в `appsettings.json` по умолчанию равна `false`. Включайте её только после основного LDAP scan. Функция читает удалённый Security log с DC и может требовать дополнительного локального/группового доступа и настройки Windows Remote Event Log firewall.

Внутри изолированного DC01, от имени администратора:

```powershell
# ТОЛЬКО ВНУТРИ DC01
Set-Location C:\IdentityRiskAnalyzer\scripts\adlab
.\11-Configure-EventLogReader.ps1 -ConfirmOptionalEventLogAccess
```

Script добавляет scanner только во встроенную **Event Log Readers** (`S-1-5-32-573`), если его там ещё нет, и отказывается продолжать при обнаружении административного членства. Он не делает scanner Domain Admin. Может потребоваться новый logon token/перезапуск приложения. Это дополнительное право только для чтения событий, а не для управления доменом.

В Web-проекте на основном ПК включите функцию и (опционально) задайте server:

```powershell
# ОСНОВНОЙ ПК, каталог src\IdentityRiskAnalyzer.Web
dotnet user-secrets set "SecurityEventLog:Enabled" "true"
dotnet user-secrets set "SecurityEventLog:Server" "dc01.adlab.test"
```

Остановите и запустите приложение заново, выполните новый scan. Приложение читает события 4625 (неуспешная аутентификация Windows), 4771 (неудачная Kerberos pre-authentication), 4776 (неудачная проверка credentials) и 4740 (блокировка аккаунта; используется как контекст). Значения по умолчанию: lookback 60 минут, максимум 10 000 событий. Пароли и password hashes не читаются.

Possible Password Spray — эвристика: не менее 10 неудачных попыток, как минимум по 5 различным именам, с одного источника в 10-минутном окне. Possible Brute Force — не менее 10 ошибок для одного имени за 10 минут; источник может отличаться. Лабораторный шаг 04 создаёт только три неудачных входа, чтобы реально заблокировать выделенного пользователя; этого недостаточно, чтобы ожидать Password Spray/Brute Force. В текущем repository нет специального безопасного сценария генерации такого event pattern. Не запускайте password spraying или перебор. Если включённый сборщик не может прочитать журнал, scan может завершиться `CompletedWithErrors`; сначала отключите опцию или исправьте доступ.

## Что готово, а что требует реального стенда

| Функция | Код/тесты в проекте | Что требует проверки на настоящем стенде |
| --- | --- | --- |
| LDAP connection, Test Connection, users/groups, LDAP paging | Реализовано; unit tests проходят. | DNS, сеть, scanner credentials и реальные ответы конкретного AD. |
| Nested Group Graph, primary group и privilege paths | Реализовано; проверяется unit tests. | Реальные members и полный путь на DC01. |
| Service account, Kerberos delegation, Risk Rules, scoring | Реализовано и тестируется. | Проверить отображение фактических атрибутов тестового AD. |
| ScanRun, SQLite snapshots и история | Реализовано и тестируется на SQLite. | Успешный настоящий LDAP scan. |
| Dashboard, historical account details, CSV | Реализовано и тестируется. | Сверить результаты реального ScanRun и открыть файлы локально. |
| Скрипты AD lab P1-16 | Созданы и проверены чтением кода. | Их нужно выполнять на изолированной Windows Server VM; в среде разработки этого README домена нет. |
| LDAPS P1-17 | Настройки и лабораторные scripts присутствуют. | Нужны CA, сертификат DC, доверенный публичный root и реальный TLS bind. |
| Security Event Log P1-18 | Collector и эвристики присутствуют; выключено по умолчанию. | Windows DC, Event Log Readers / remote event log access и подходящие реальные события. |
| Exchange delegation | Контракты/настройки есть; реального Exchange collector нет. | Инвентаризация Exchange в текущей поставке не выполняется. |

Автоматические tests и лабораторные scripts не доказывают, что реальный Windows Server был поднят. Отмечайте в отчёте demo только то, что вы сами увидели на конкретном стенде.

## Кратчайшая подготовка к Hackathon

Для базовой демонстрации Project 1 достаточно:

1. `DC01` работает в изолированной сети.
2. Все строки `06-Verify-Lab.ps1` — `OK`.
3. LDAP 389 Test Connection проходит под `ADLAB\svc_ira_scanner`.
4. Страницы Users и Groups показывают настоящие lab objects.
5. ScanRun завершился `Completed` (либо вы можете объяснить recoverable errors в `CompletedWithErrors`).
6. Dashboard показывает реальные сохранённые findings.
7. В исторических деталях `lab_nested_admin` виден путь до Domain Admins.
8. `svc_sql` показывает service/PNE risks.
9. Accounts CSV и Findings CSV скачиваются и открываются.

LDAPS и Event Log можно показать как дополнительное преимущество, если они заранее реально проверены. Не тратьте время на них до рабочего 389 scan.

## Сценарий презентации для жюри на 5–7 минут

| Время | Что открыть / сказать |
| --- | --- |
| 0:00–0:40 | Проблема: в AD права часто приходят через вложенные группы; одного списка прямых участников недостаточно. |
| 0:40–1:10 | Схема: read-only LDAP → локальный анализ → SQLite snapshot → Dashboard. Покажите, что приложение не меняет AD. |
| 1:10–2:00 | Покажите `DC01` и коротко объясните, что users/groups в домене — реальные лабораторные объекты. Не тратьте время на настройку VM во время pitch. |
| 2:00–3:00 | Откройте `/Scans`, покажите уже подготовленный успешный ScanRun и сохранённый статус. Не запускайте новый scan, если время ожидания непредсказуемо. |
| 3:00–4:00 | Dashboard: Security Score, findings по severity, privileged/service accounts и Top Risky Accounts. Объясните направление шкал. |
| 4:00–5:20 | Account Details для `lab_nested_admin`: покажите полный path `пользователь → DemoHelpDesk → DemoITAdmins → Domain Admins`, Direct/Nested и evidence. |
| 5:20–6:00 | Откройте `svc_sql` или `svc_constrained`, покажите SPN/target и конкретные RuleId/recommendations. |
| 6:00–6:40 | Покажите history Scan A / B или CSV export. Подчеркните, что старый snapshot не перезаписывается. |

Пример текста: «Identity Risk Analyzer подключается к Active Directory только для чтения. Мы не просто отмечаем, что пользователь администратор: сохраняем путь через вложенные группы, который привёл его к привилегированной группе. Каждый scan — исторический снимок с evidence и рекомендациями. Команда безопасности может перепроверить результат в UI и скачать CSV».

## За день до защиты

- [ ] Host-only сеть изолирует VM; DC не подключён через Bridged к корпоративной сети.
- [ ] Снимок `C - AD и risk scenarios готовы` создан.
- [ ] VM загружается, `Get-ADDomain` возвращает `adlab.test`.
- [ ] `Resolve-DnsName dc01.adlab.test` и TCP 389 проходят с основного ПК.
- [ ] Scanner username/password проверены, scanner не состоит в admin groups.
- [ ] `06-Verify-Lab.ps1` показывает 14 OK.
- [ ] `dotnet build` и `dotnet test` проходят из корня repository.
- [ ] Test Connection проходит; Users/Groups показывают lab objects.
- [ ] Есть недавний успешный ScanRun; Dashboard заполнен.
- [ ] Nested path и `svc_sql` findings проверены в исторических details.
- [ ] Accounts CSV и Findings CSV открываются, кириллица отображается.
- [ ] На время выступления отключены лишние настройки, о которых нельзя уверенно рассказать (например, Event Log/LDAPS, если не проверяли).

## Прямо перед демонстрацией

1. Запустите VirtualBox и включите `DC01`; дождитесь входа Windows и запуска AD DS/DNS.
2. На основном ПК выполните `Resolve-DnsName dc01.adlab.test` и `Test-NetConnection dc01.adlab.test -Port 389`.
3. Запустите приложение из `src\IdentityRiskAnalyzer.Web` и откройте адрес из строки `Now listening on`.
4. Не запускайте scan в последний момент: откройте заранее завершённый ScanRun и проверьте, что Dashboard показывает его.
5. Подготовьте две вкладки браузера: Dashboard и historical details `lab_nested_admin`.
6. Не показывайте `dotnet user-secrets list`, пароль scanner, полный production DNS или содержимое пользовательской базы на большом экране.

## Как проект устроен внутри

Текущий Scan Pipeline:

```text
LDAP collection users + groups (+ MSA/gMSA)
  → Group Graph и shortest membership paths
  → Privileged Group Analysis
  → Service Account Classification
  → Kerberos Delegation Analysis
  → Duplicate SPN analysis
  → Risk Rules (и Event Log, если отдельно включён)
  → Object Risk Scores и AD Security Score
  → атомарное сохранение снимка в SQLite
  → Dashboard / historical details / CSV
```

Контроллеры принимают HTTP-запросы и передают работу сервисам. LDAP, граф групп, privilege analysis, делегирование, правила, scoring и запросы Dashboard находятся в отдельных сервисах. LDAP collection использует paged searches, а большие group `member` attributes читаются по частям (ranged retrieval). Group Graph анализирует уже полученные users/groups локально и не делает LDAP-запрос для каждого member. В БД каждый scan создаёт новые строки с собственным `ScanRunId`; успешная история не удаляется следующим запуском.

## Справочник текущих Risk Rule IDs

Severity и RiskPoints сверены с `src/IdentityRiskAnalyzer.Web/appsettings.json`. Условия сверены с реализациями правил. Severity находки и Risk Level объекта — разные вещи.

| RuleId | Название / условие срабатывания | Severity | Points |
| --- | --- | ---: | ---: |
| `IRA-ACCOUNT-001` | Включённая учётная запись имеет `lastLogonTimestamp` не моложе настроенного порога неактивности (по умолчанию 90 дней); отсутствующий timestamp не срабатывает. | Medium | 15 |
| `IRA-ACCOUNT-002` | Дата окончания аккаунта раньше времени анализа. | Low | 10 |
| `IRA-ACCOUNT-003` | Computed UAC указывает на текущую блокировку (`LOCKOUT`). Исторического `lockoutTime` одного недостаточно. | Low | 5 |
| `IRA-PASSWORD-001` | Установлен флаг `DONT_EXPIRE_PASSWORD`. | Medium | 15 |
| `IRA-PASSWORD-002` | `pwdLastSet` достиг настроенного возраста (по умолчанию 180 дней). Нет даты — нет finding. | Medium | 10 |
| `IRA-SERVICE-001` | Классифицированный service account настроен с Password Never Expires. | High | 25 |
| `IRA-PRIV-001` | Прямое членство в настроенной privileged group; finding может быть отдельным для каждой группы. | High | 30 |
| `IRA-PRIV-002` | До configured privileged group ведёт вложенный путь. Evidence содержит полный path и depth. | High | 30 |
| `IRA-PRIV-003` | У аккаунта есть membership paths к двум или более различным privileged groups. | Medium | 20 |
| `IRA-PRIV-004` | Включённая privileged учётная запись неактивна дольше строгого порога (по умолчанию 30 дней). | High | 30 |
| `IRA-DELEGATION-001` | Установлен TRUSTED_FOR_DELEGATION (unconstrained delegation). | Critical | 50 |
| `IRA-DELEGATION-002` | Настроена constrained delegation с целевыми services. | Medium | 20 |
| `IRA-DELEGATION-003` | Protocol Transition настроен вместе с delegation targets. | High | 35 |
| `IRA-DELEGATION-004` | Присутствует RBCD attribute; ACL descriptor в MVP не разбирается. | High | 25 |
| `IRA-AD-001` | Обнаружен непустой SIDHistory; наличие требует проверки, но само по себе не доказывает misuse. | Medium | 15 |
| `IRA-SPN-001` | Один SPN назначен нескольким различным объектам. | High | 25 |
| `IRA-AUTH-001` | Security Event Log эвристически указывает на password spray: по умолчанию 10 ошибок/5 имён/один source/10 минут. | High | 30 |
| `IRA-AUTH-002` | Security Event Log эвристически указывает на brute force: по умолчанию 10 ошибок одного имени/10 минут. | High | 25 |

Пороги текущего `RiskSettings`: `InactiveUserDays=90`, `InactivePrivilegedUserDays=30`, `OldPasswordDays=180`; уровни score начинаются с 25 (Medium), 50 (High), 75 (Critical). Rules настраиваются конфигурацией; при изменении настроек ожидаемые severity/points также могут измениться.

## Безопасность и границы проекта

* LDAP collector и analyzers читают AD; автоматического remediation нет.
* Приложение не отключает пользователей и компьютеры, не удаляет group memberships и не меняет Kerberos delegation.
* Пароли AD в LDAP не запрашиваются. LDAP scanner password не отображается в UI и не сохраняется в SQLite snapshot.
* Scanner — обычный Domain User, не Domain Admin. Event Log optional script может добавить его в Event Log Readers только для дополнительной функции.
* Recommendations — подсказки аналитику; решение и любые реальные изменения выполняет человек по своей процедуре.
* Не включайте приложение в публичный интернет без отдельной production-подготовки. Текущая инструкция предназначена для локальной демонстрации.
* Все scripts под `scripts/adlab` предназначены только для изолированного `adlab.test`. В них есть проверки домена, имени DC, OU и подтверждения, но это не разрешает запускать их в production.
* Exchange: в текущей поставке есть настройки и контракты, но нет работающего Exchange collector. Exchange permissions не сканируются.

## Диагностика ошибок

Сначала исправляйте по порядку: DNS → TCP-порт → credentials → Base DN → AD properties → запуск scan → сохранённые результаты. Одна проблема за раз.

| Симптом | Что проверить | Что делать |
| --- | --- | --- |
| `Resolve-DnsName dc01.adlab.test` не работает | На основном ПК адрес Host-only DNS; на DC запущен DNS; DC имеет статический IP. | На DC: `Get-Service DNS,NTDS`. На ПК: `Resolve-DnsName dc01.adlab.test -Server 192.168.56.10`. Проверьте, что серверный адрес и host-only DNS равны фактическому IP DC. |
| `ping` не отвечает | ICMP может быть запрещён firewall. | Не диагностируйте только ping. Выполните `Test-NetConnection dc01.adlab.test -Port 389`. |
| TCP 389 закрыт | VM запущена, Adapter 1 Host-only, адреса в одной подсети, AD DS запущен. | На DC: `Get-Service NTDS,DNS`; на ПК: `Test-NetConnection dc01.adlab.test -Port 389`. Не включайте Bridged «для проверки». |
| Test Connection: authentication failed | Username/Password оба заданы и правильны; `svc_ira_scanner` включён и не заблокирован. | На DC: `Get-ADUser svc_ira_scanner -Properties Enabled,LockedOut,DistinguishedName`. Повторно выполните шаг 05, при необходимости вручную безопасно сбросьте scanner password в лаборатории, затем обновите User Secret. Не используйте Domain Admin credentials как обход. |
| Test Connection: LDAP server unavailable / timeout | DNS, IP, TCP 389, VM power state, firewall. | Повторите `Resolve-DnsName` и `Test-NetConnection`. Проверьте, что подключение не идёт к неправильному адаптеру/IP. |
| Test Connection: Base DN query failed | Опечатка в `ActiveDirectory:BaseDn`. | На основном ПК проверьте `dotnet user-secrets list`; значение должно быть `DC=adlab,DC=test`. На DC выполните `Get-ADDomain | Select-Object DistinguishedName`. |
| Users пусты или страница показывает ошибку | Users script шаг 03 прошёл, Base DN — весь домен, scanner валиден. | На DC: `Get-ADUser -SearchBase 'OU=HackathonLab,DC=adlab,DC=test' -SearchScope Subtree -Filter *`. Затем проверьте Users page и журнал Web приложения. Страница показывает ограниченное число записей, но lab users должны быть среди первых. |
| Groups пусты | Шаг 03 создал группы; Base DN полный; LDAP search разрешён. | На DC: `Get-ADGroup -SearchBase 'OU=Groups,OU=HackathonLab,DC=adlab,DC=test' -Filter *`. На ПК повторите Test Connection, затем `/ActiveDirectory/Groups`. |
| Scan `Failed` | Откройте страницу ScanRun и безопасное error message. | Если сообщение про LDAP — повторите DNS/389/credentials/Base DN проверки выше. Если про SQLite — остановите второй процесс приложения и убедитесь, что папка Web доступна для записи. После исправления запустите новый scan; Failed scan остаётся в истории. |
| Scan `CompletedWithErrors` | `ErrorsCount`, application logs, включённые optional integrations. | Если Event Log включён, временно отключите `SecurityEventLog:Enabled` и повторите основной LDAP scan. Проверьте, что важные данные сохранились; этот статус означает partial/recoverable error, а не обязательно потерю snapshot. |
| Ожидаемого RuleId нет | `06-Verify-Lab.ps1`, актуальный ScanRun, объект из полного Base DN, состояние UAC/member. | Убедитесь, что смотрите детали объекта именно последнего завершённого scan. Сверьте конкретный сценарий с таблицей expected findings. Не ждите stale/password age/duplicate SPN/SIDHistory в чистой lab. |
| `lab_nested_admin` не показывает Domain Admins | Вложена ли `DemoITAdmins` в Domain Admins, `DemoHelpDesk` в `DemoITAdmins`, пользователь в `DemoHelpDesk`. | На DC выполните `06-Verify-Lab.ps1`. Проверьте `BaseDn=DC=adlab,DC=test`; если ранее выполняли Scan B, восстановите nested edge командой Add-ADGroupMember из секции истории и выполните новый scan. |
| Service account не распознался | SPN действительно назначен ожидаемому AD user или это реальный gMSA. | На DC: `Get-ADUser svc_sql -Properties ServicePrincipalName | Select-Object SamAccountName,ServicePrincipalName`. Для gMSA: `Get-ADServiceAccount gmsa_demo -Properties objectClass`. Затем выполните новый scan. |
| `lab_locked_user` не locked | Действует ли lab-only PSO и истёк ли прежний период блокировки. | На DC: `Get-ADUser lab_locked_user -Properties LockedOut,'msDS-User-Account-Control-Computed'`; `Get-ADUserResultantPasswordPolicy lab_locked_user`. После истечения 30 минут снова выполните `04-Configure-RiskScenarios.ps1 -ConfirmLabChanges`, затем `06-Verify-Lab.ps1`. |
| Dashboard пустой | Есть ли завершённый успешный scan. | Dashboard намеренно не показывает Failed scan как основной источник. Откройте `/Scans`, исправьте ошибку и выполните успешный scan. |
| Dashboard показывает старые данные | Новый scan Failed/Running/Cancelled либо вы смотрите historical scan. | Dashboard использует последний `Completed`/`CompletedWithErrors`; откройте `/Scans` и проверьте status и время. Historical details намеренно не обновляются из текущего AD. |
| CSV route возвращает 404 | Scan завершён и его ID верный? | Экспорт существует только для `Completed` и `CompletedWithErrors`. Откройте `/Scans/{id}` и используйте links оттуда. |
| Port 636 закрыт | LDAPS-глава ещё не выполнена или DC не перезагружен. | Проверьте CA, шаги 08–10 и `Test-NetConnection dc01.adlab.test -Port 636`. Не ждите 636 до отдельной настройки сертификата. |
| LDAPS: certificate name mismatch | Подключение использует IP/alias, которого нет в SAN/CN. | Верните Server `dc01.adlab.test`; проверьте сертификат на DC. Не отключайте certificate validation. IP отклоняется конфигурационной проверкой раньше bind. |
| LDAPS: untrusted root | CA certificate не импортирован в системное Trusted Root хранилище ПК приложения. | Перенесите только публичный `.cer`, импортируйте в `Cert:\LocalMachine\Root` от администратора и перезапустите приложение. Не переносите `.pfx` или private key. |
| LDAPS 636 открывается, но Test Connection падает | TCP reachability не подтверждает TLS trust/hostname/validity. | Запустите `10-Verify-Ldaps.ps1 -Credential ...`; проверьте EKU, dates, SAN, trust chain и LDAP bind. |
| Event Log: Access denied / `CompletedWithErrors` | Event Log Readers, Remote Event Log firewall/policy, новый scanner logon token. | Только в lab выполните `11-Configure-EventLogReader.ps1 -ConfirmOptionalEventLogAccess`, обновите scanner session и проверьте remote event log access. Если это не нужно для demo, выключите `SecurityEventLog:Enabled`. |
| gMSA script failed | Domain functional level, KDS root key, ActiveDirectory/Kds modules, один DC. | На DC: `Get-ADDomain | Select-Object DomainMode`; `Get-KdsRootKey`; `Get-ADDomainController -Filter *`. Не создавайте дополнительные root keys вручную и не запускайте сценарий в многоконтроллерном домене. |
| `dotnet` не найден или нет SDK | Установлен Runtime вместо SDK либо терминал был открыт до установки. | Установите .NET 10 SDK с официальной страницы, закройте/откройте PowerShell и выполните `dotnet --list-sdks`. |
| SQLite file locked / database error | Два процесса приложения либо нет права записи в project folder. | Остановите другие `dotnet run`; проверьте `Get-Item .\identity-risk-analyzer.db`. Не удаляйте DB, если хотите сохранить snapshots. |

## Удаление лабораторных объектов

Не запускайте cleanup до окончания демонстрации и пока не сохранены нужные снимки/CSV. Скрипт удаляет `OU=HackathonLab` и все дочерние объекты, lab PSO `HackathonLab-LockoutPSO` (только с ожидаемым маркером), а перед удалением снимает созданные внешние членства из Domain Admins, Backup Operators, Server Operators и Event Log Readers. Удаление OU рекурсивное и необратимое без восстановления.

Cleanup требует локального администратора, проверяет текущий домен `adlab.test`, компьютер `DC01`, единственный DC, точный DN и marker; также требует параметр `-ConfirmLabCleanup` и вручную напечатать `adlab.test/HackathonLab`. Внутри DC01:

```powershell
# ТОЛЬКО ПОСЛЕ ЗАВЕРШЕНИЯ ДЕМО, ВНУТРИ DC01
Set-Location C:\IdentityRiskAnalyzer\scripts\adlab
.\99-Remove-LabObjects.ps1 -ConfirmLabCleanup
```

Внимательно прочитайте приглашение и введите точную строку только если готовы удалить test objects. Cleanup **не** удаляет KDS root key, AD DS, домен, VM или CA-сертификаты P1-17. Он не демонтирует Windows Server и не удаляет VM; чтобы удалить всю одноразовую лабораторию, выключите и удалите её в VirtualBox после сохранения нужного. Snapshot можно использовать для возврата.

## Что реально проверено и что нет

При подготовке этого README были изучены текущие .NET-проекты, конфигурация, controllers/routes, rule settings и все файлы `scripts/adlab`. Сами Windows Server AD DS scripts требуют одноузловой Windows Server домен и здесь не исполнялись. В частности, реальный DC, LDAP 389/LDAPS 636, сертификатная цепочка, Event Log permissions и end-to-end scan против настоящего AD нельзя считать проверенными только по коду или unit tests.

Перед выступлением отмечайте эти пункты только после фактического прохождения на своей VM. Не добавляйте фиктивные пользователей в приложение: лабораторные accounts должны приходить из настоящего AD.

## Итоговые проверки repository

Из корня repository, на основном ПК:

```powershell
dotnet restore
dotnet build
dotnet test
```

Успешная сборка и тесты подтверждают автоматические проверки .NET. Чтобы подтвердить настоящий AD, отдельно пройдите все шаги до Test Connection, Start Scan и сверки `EXPECTED_FINDINGS.md`.
