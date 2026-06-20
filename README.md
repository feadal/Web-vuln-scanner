# webscan

[![CI](https://github.com/your-org/webscan/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/webscan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)

**webscan** — лёгкий модульный сканер веб-уязвимостей на Python для **авторизованного**
тестирования на проникновение, обучения и оценки безопасности своих приложений.

Инструмент делает преимущественно *пассивные* и низкоинтенсивные проверки: анализирует
HTTP-заголовки безопасности, флаги cookie, раскрытие версий ПО, конфигурацию TLS/редиректов,
наличие типичных чувствительных файлов и небезопасные HTML-формы. Он не эксплуатирует
уязвимости и не выполняет деструктивных действий.

---

## ⚠️ Юридическое предупреждение

Используйте `webscan` **только** против систем, которыми вы владеете или на тестирование
которых у вас есть явное письменное разрешение. Несанкционированное сканирование чужих
систем во многих юрисдикциях является преступлением (например, CFAA в США, ст. 272–274 УК РФ).
Авторы не несут ответственности за неправомерное использование. Подробнее — в [SECURITY.md](SECURITY.md).

---

## Возможности

| Проверка | Что ищет | Тип |
|---|---|---|
| `security-headers` | Отсутствие CSP, HSTS, X-Frame-Options, X-Content-Type-Options и др. | пассивная |
| `cookies` | Cookie без флагов `Secure` / `HttpOnly` / `SameSite` | пассивная |
| `server-disclosure` | Раскрытие версий через `Server`, `X-Powered-By`, `X-AspNet-Version` | пассивная |
| `tls` | Использование HTTP, отсутствие редиректа на HTTPS, ошибки сертификата | пассивная |
| `sensitive-files` | Доступные `.git/`, `.env`, бэкапы, `robots.txt`, листинг директорий | низкоинтенсивная |
| `forms` | Формы по HTTP, поля пароля с `autocomplete`, отсутствие CSRF-токена | пассивная |

## Установка

```bash
git clone https://github.com/your-org/webscan.git
cd webscan
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Использование

```bash
# Базовое сканирование
webscan https://example.com

# Выбрать конкретные проверки
webscan https://example.com --checks security-headers,cookies,tls

# Вывод в JSON (для CI / отчётов)
webscan https://example.com --format json --output report.json

# Не проверять TLS-сертификат (для self-signed в лаборатории)
webscan https://localhost:8443 --insecure

# Показать список доступных проверок
webscan --list-checks
```

Пример вывода:

```
webscan 0.1.0 — target: https://example.com

[HIGH]   security-headers  Отсутствует Strict-Transport-Security (HSTS)
[MEDIUM] cookies           Cookie 'session' без флага HttpOnly
[LOW]    server-disclosure Заголовок Server раскрывает версию: nginx/1.18.0
[INFO]   tls               HTTP корректно перенаправляется на HTTPS

Итого: 4 находки (1 high, 1 medium, 1 low, 1 info)
```

Код возврата: `0` — находок уровня medium+ нет, `1` — есть (удобно для пайплайнов CI).

## Разработка

```bash
pip install -e ".[dev]"
pytest          # тесты
ruff check .    # линтер
```

Добавить свою проверку просто — создайте класс-наследник `Check` в `webscan/checks/`
и зарегистрируйте его в `webscan/checks/__init__.py`. См. [CONTRIBUTING.md](CONTRIBUTING.md).

## Лицензия

[MIT](LICENSE)
