# GGT Security Lists

Централизирани блоклисти за сигурност на **Global Gaming Technology Ltd.** — автоматично обновявани от [GitHub Advisory Database](https://github.com/advisories?query=type%3Amalware).

## Какво съдържа?

| Файл | Описание | Записи |
|------|----------|--------|
| `malicious-npm-packages.txt` | Известни зловредни npm пакети | Автоматично обновяван |
| `malicious-npm-patterns.txt` | Regex шаблони за подозрителни npm имена | Ръчно поддържан |
| `malicious-nuget-packages.txt` | Известни зловредни NuGet пакети | Автоматично обновяван |
| `malicious-nuget-patterns.txt` | Regex шаблони за подозрителни NuGet имена | Ръчно поддържан |
| `malware-names.txt` | Имена на известен малуер (encoded) | Ръчно поддържан |
| `suspicious-ports.txt` | Портове използвани от малуер | Ръчно поддържан |
| `suspicious-vscode-extensions.txt` | Подозрителни VS Code разширения | Ръчно поддържан |
| `known-bad-certs.txt` | Фалшиви root сертификати | Ръчно поддържан |
| `safe-*.txt` | Whitelists за известни безопасни процеси/DNS | Ръчно поддържан |
| `system-dlls.txt` | Легитимни системни DLL файлове | Ръчно поддържан |
| `sensitive-env-vars.txt` | ENV променливи с credentials | Ръчно поддържан |
| `suspicious-*-patterns.txt` | Шаблони за подозрителни команди (encoded) | Ръчно поддържан |

## Автоматично обновяване

GitHub Actions workflow тегли нови малициозни пакети **всеки ден в 06:00 UTC** от GitHub Advisory Database (`type=malware`) и автоматично commit-ва промените.

Може да се стартира и ръчно от **Actions → Update Blocklists → Run workflow**.

## Ползване от скриптове

Скриптовете от [security-workstation-scanner](https://git.bluecroco.com/security/security-workstation-scanner) автоматично свалят последните блоклисти от това хранилище при стартиране.

### Raw URL формат

```
https://raw.githubusercontent.com/Global-Gaming-Technology-Ltd/security-scan-lists/main/lists/FILENAME
```

> Организация: `Global-Gaming-Technology-Ltd` / Хранилище: `security-scan-lists`

### Пример (curl)

```bash
curl -sS --connect-timeout 5 \
  "https://raw.githubusercontent.com/Global-Gaming-Technology-Ltd/security-scan-lists/main/lists/malicious-npm-packages.txt" \
  -o lists/malicious-npm-packages.txt
```

### Пример (PowerShell)

```powershell
try {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Global-Gaming-Technology-Ltd/security-scan-lists/main/lists/malicious-npm-packages.txt" `
        -OutFile "lists\malicious-npm-packages.txt" -TimeoutSec 5 -UseBasicParsing
} catch { }
```

## ENCODED:REVERSE файлове

Някои файлове съдържат имена на хакерски инструменти (mimikatz, CobaltStrike и др.), които антивирусните програми могат да маркират. Тези файлове имат маркер `# ENCODED:REVERSE` на първи ред и всеки запис е записан наобратно. Скриптовете ги декодират автоматично при четене.

## Лиценз

Вътрешен инструмент на **Global Gaming Technology Ltd.**
