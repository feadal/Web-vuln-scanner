# Как внести вклад

Спасибо за интерес к проекту! Вклад приветствуется — от исправления опечаток до новых проверок.

## Окружение

```bash
git clone https://github.com/your-org/webscan.git
cd webscan
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Перед отправкой PR

```bash
ruff check .     # линтер должен проходить без ошибок
pytest -q        # все тесты зелёные
```

## Добавление новой проверки

1. Создайте файл `webscan/checks/my_check.py` с классом — наследником `Check`:

   ```python
   from webscan.checks.base import Check
   from webscan.models import Finding, ScanContext, Severity

   class MyCheck(Check):
       name = "my-check"
       description = "Что проверяет (одной строкой)"

       def run(self, ctx: ScanContext) -> list[Finding]:
           findings = []
           # ... ваша логика ...
           return findings
   ```

2. Зарегистрируйте класс в `ALL_CHECKS` в `webscan/checks/__init__.py`.
3. Добавьте юнит-тесты в `tests/` (используйте офлайн-моки, не ходите в сеть).
4. Обновите таблицу проверок в `README.md`.

## Принципы

- **Безопасность по умолчанию.** Проверки должны быть пассивными или низкоинтенсивными.
  Никакой эксплуатации, перебора паролей, DoS или деструктивных запросов.
- **Минимум зависимостей.** Старайтесь обходиться стандартной библиотекой и `requests`.
- **Без ложных срабатываний.** Лучше пропустить, чем выдать уверенную ложную находку.
