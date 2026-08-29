# PassOne

> Самодостаточный Windows-клиент для менеджера паролей [`pass`](https://www.passwordstore.org/) — без GnuPG, Git и SSH в системе.

[![CI](https://github.com/oxcafedead/passone/actions/workflows/ci.yml/badge.svg)](https://github.com/oxcafedead/passone/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/oxcafedead/passone)](https://goreportcard.com/report/github.com/oxcafedead/passone)
[![Go Version](https://img.shields.io/github/go-mod/go-version/oxcafedead/passone)](./go.mod)

PassOne — это нативное Windows-приложение для работы с password-store (pass-формат: `.gpg` + `.gpg-id` + git).
В отличие от большинства клиентов, оно не требует установленных `gpg.exe`, `git.exe` или `ssh.exe`:
вся криптография, git-транспорт и SSH реализованы на Go и встроены в один бинарник.

- **CLI** — `passone.exe` для терминала и автоматизации.
- **GUI** — `passone-ui.exe`, десктопное приложение на Wails v2 + Svelte 5 с треем и авто-блокировкой.

> ⚠️ Проект ориентирован исключительно на Windows: используется DPAPI, systray, реестр темы и Win32-clipboard.

---

## Возможности

- 🔐 **OpenPGP «из коробки»** — импорт приватных PGP-ключей, шифрование/расшифровка `*.gpg` через [`ProtonMail/go-crypto`](https://github.com/ProtonMail/go-crypto).
- 🗝️ **SSH «из коробки»** — импорт OpenSSH-ключей (`ed25519`, RSA), хост-ключи, `known_hosts`, git over SSH через [`go-git`](https://github.com/go-git/go-git).
- 📂 **Совместимый формат** — читает и пишет обычный pass-стор: `.gpg-id`, подпапки, `*.gpg`.
- 🔄 **Git-синхронизация** — `clone`, `status`, `sync` (fetch/pull/push) без внешнего git.
- 🔒 **Безопасность** — ключи хранятся запечатанными в Windows DPAPI; в памяти находятся только после `unlock`; авто-блокировка по таймауту; обнуление буферов.
- 📋 **Буфер обмена** — `copy` копирует пароль и автоматически очищает clipboard через настраиваемое время.
- 🪟 **GUI** — системный трей, одно окно, поддержка светлой/тёмной темы, single-instance lock.

---

## Быстрый старт

### Системные требования

- Windows 10/11 (x64)
- [Go](https://go.dev/) 1.26+
- [Node.js](https://nodejs.org/) + npm (для сборки GUI)
- [Wails CLI](https://wails.io/docs/gettingstarted/installation) (только для сборки GUI)

### Сборка CLI

```powershell
go build -o passone.exe ./cmd/app
```

### Сборка GUI

```powershell
cd cmd/gui/frontend
npm ci
npm run build
cd ../../..

cd cmd/gui
wails build -skipbindings -s -nopackage -clean
```

Готовый бинарник появится в `cmd/gui/build/bin/passone-ui.exe`.

---

## Использование CLI

```text
PassOne - native Windows pass client (CLI proof of concept)

Usage: passone <command> [arguments]

Store / keys
  init                         Create the application data directory
  import-pgp-key <file>        Import an armored OpenPGP private key
  import-ssh-key <file>        Import an OpenSSH private key (~/.ssh/id_ed25519)
  public-key                   Print the SSH public key (add it to GitHub)
  open <dir>                   Open an existing local pass store
  clone <url> [dir]            Clone a git pass store over SSH
  test-ssh <host>              Verify the host key and test SSH auth
  known-hosts                  List trusted SSH host keys

Passwords
  list [prefix]                List password paths (no decryption)
  show <path> [--full]         Show the password (first line unless --full)
  copy <path>                  Copy the password to the clipboard (auto-clears)
  save <path> <file>           Save encrypted plaintext from a file ('-' = stdin)
  edit <path> [--no-commit]    Edit plaintext, re-encrypt (atomic), then commit
  rm   <path>                  Remove a password entry

Git
  status                       Git status of the store
  sync                         Fetch, merge and push

Session
  unlock                       Unlock stored keys (prompts for passphrases)
  lock                         Lock: drop decrypted keys from memory
  state                        Show lock state and configuration
  config                       Show configuration
```

### Пример первого запуска

```powershell
# 1. Инициализировать директорию данных
.\passone.exe init

# 2. Импортировать PGP-ключ
.\passone.exe import-pgp-key .\private-key.asc

# 3. Импортировать SSH-ключ
.\passone.exe import-ssh-key $env:USERPROFILE\.ssh\id_ed25519

# 4. Открыть или клонировать существующий pass-стор
.\passone.exe open C:\Users\Me\pass-store
# или
.\passone.exe test-ssh github.com
.\passone.exe clone git@github.com:username/pass-store.git

# 5. Разблокировать и работать
.\passone.exe unlock
.\passone.exe list
.\passone.exe show github/personal
.\passone.exe copy github/personal
```

---

## Использование GUI

1. Запустите `passone-ui.exe`.
2. Импортируйте ключи через интерфейс настроек.
3. Откройте или клонируйте pass-стор.
4. Приложение живёт в системном трее; закрытие окна сворачивает его, а не завершает.
5. При бездействии сессия автоматически блокируется (время настраивается).

---

## Архитектура

```text
cmd/
  app/            CLI-входная точка (passone.exe)
  gui/            Wails v2 GUI (passone-ui.exe)
  gui/frontend/   Svelte 5 + Vite + Tailwind 4

internal/
  app/            Ядро: разблокировка, операции с паролями, git-синхронизация, конфиг
  ui/             Фасад Wails над internal/app
  pgp/            OpenPGP (ProtonMail/go-crypto)
  sshx/           Парсинг OpenSSH-ключей, signer, known_hosts
  gitx/           Pure-Go git (go-git)
  store/          pass-формат: *.gpg, .gpg-id
  security/       DPAPI, обнуление памяти
  config/         Конфиг, пути, ACL
  cliputil/       Работа с clipboard и автоочистка

tests/
  fixtures/       Тестовые данные
  interop/        PowerShell-интеграция с настоящим GnuPG
```

---

## Безопасность

- **Хранение ключей:** приватные ключи хранятся в зашифрованном виде (AES-256-GCM) в `%LOCALAPPDATA%\PassOne`; ключ шифрования защищён Windows DPAPI для текущего пользователя.
- **Ключи в памяти:** расшифрованные ключи существуют только после явного `unlock` и удаляются при `lock` или авто-блокировке (best-effort обнуление буферов).
- **SSH-хосты:** ключи хостов проверяются при первом контакте и сохраняются; при изменении подключение прерывается.
- **Буфер обмена:** пароль автоматически удаляется из clipboard через настроенное время.
- **Атомарность:** запись пароля производится во временный файл и только после успешного шифрования заменяет старый.

---

## Разработка

### Форматирование и линтинг

```powershell
gofmt -w .
go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8 run --timeout=5m
```

### Тестирование

> Перед `go test ./...` необходимо собрать frontend GUI, иначе `go:embed all:frontend/dist` не найдёт файлы.

```powershell
cd cmd/gui/frontend
npm ci
npm run build
cd ../../..

go test ./...
```

Запуск отдельного пакета/теста:

```powershell
go test ./internal/app
go test ./internal/app -run TestImportUnlockDecryptFlow
```

Горячая перезагрузка frontend:

```powershell
cd cmd/gui/frontend
npm run dev
```

### Git hooks

В репозитории настроен `pre-commit` hook (директория `.githooks`). Перед каждым коммитом он автоматически:

1. Проверяет, что все staged Go-файлы отформатированы `gofmt`.
2. Запускает `golangci-lint`.

Если какая-либо проверка не проходит, коммит прерывается.

Чтобы включить hooks после клонирования репозитория, выполните:

```powershell
git config core.hooksPath .githooks
```

(В текущем рабочем клоне hooks уже активированы.)

### Интеграционные тесты

`tests/interop/run.ps1` — ручная проверка совместимости с реальным GnuPG. Требует собранный `passone.exe` и установленный GnuPG. Не входит в `go test ./...`.

---

## Переменные окружения

| Переменная | Описание |
|------------|----------|
| `PASSONE_DIR` | Переопределяет директорию данных приложения. По умолчанию: `%LOCALAPPDATA%\PassOne`. |

---

## Участие в проекте

PR и issue приветствуются! Перед отправкой:

1. `gofmt -w .` (выполняется автоматически в `pre-commit` hook)
2. `go test ./...`
3. `golangci-lint run --timeout=5m` (выполняется автоматически в `pre-commit` hook)

Если `pre-commit` hook настроен, пункты 1 и 3 пройдут автоматически при коммите.

См. также [AGENTS.md](./AGENTS.md) — краткие заметки для контрибьюторов и агентов.

---

## Лицензия

Укажите вашу лицензию в файле `LICENSE`.
