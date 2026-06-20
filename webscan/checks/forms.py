"""Inspect HTML forms for insecure submission and password-handling patterns.

Uses the stdlib HTML parser so the project keeps a single runtime dependency.
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urlparse

from webscan.checks.base import Check
from webscan.models import Finding, ScanContext, Severity


class _Form:
    def __init__(self, attrs: dict[str, str]) -> None:
        self.action = attrs.get("action", "")
        self.method = (attrs.get("method") or "get").lower()
        self.inputs: list[dict[str, str]] = []

    @property
    def has_password(self) -> bool:
        return any(i.get("type", "").lower() == "password" for i in self.inputs)

    @property
    def has_csrf_token(self) -> bool:
        for i in self.inputs:
            name = (i.get("name") or "").lower()
            if i.get("type", "").lower() == "hidden" and any(
                tok in name for tok in ("csrf", "token", "authenticity", "nonce", "_token")
            ):
                return True
        return False


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[_Form] = []
        self._current: _Form | None = None

    def handle_starttag(self, tag, attrs):
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current = _Form(attr_map)
            self.forms.append(self._current)
        elif tag in ("input", "textarea", "select") and self._current is not None:
            self._current.inputs.append(attr_map)

    def handle_endtag(self, tag):
        if tag == "form":
            self._current = None


class FormSecurityCheck(Check):
    name = "forms"
    description = "Анализирует HTML-формы (HTTP-отправка, пароли, CSRF-токены)"

    def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.base_html:
            return []

        parser = _FormParser()
        try:
            parser.feed(ctx.base_html)
        except Exception:  # malformed HTML — bail out quietly
            return []

        page_is_https = (ctx.base_response.url if ctx.base_response else ctx.target).lower().startswith(
            "https://"
        )
        findings: list[Finding] = []

        for idx, form in enumerate(parser.forms):
            label = form.action or f"form #{idx + 1}"
            action_url = ctx.client.join(ctx.target, form.action) if form.action else ctx.target

            if _submits_over_http(action_url, page_is_https):
                findings.append(
                    self.finding(
                        title=f"Форма отправляет данные по HTTP ({label})",
                        severity=Severity.HIGH if form.has_password else Severity.MEDIUM,
                        description="Данные формы передаются без шифрования.",
                        evidence=f"action={form.action or '(текущая страница)'}",
                        remediation="Отправляйте формы только на HTTPS-адреса.",
                        url=action_url,
                    )
                )

            if form.has_password:
                if not form.has_csrf_token and form.method == "post":
                    findings.append(
                        self.finding(
                            title=f"Форма с паролем без CSRF-токена ({label})",
                            severity=Severity.MEDIUM,
                            description="Не найдено скрытое поле, похожее на анти-CSRF токен.",
                            remediation="Добавьте проверяемый на сервере CSRF-токен в форму.",
                            url=action_url,
                        )
                    )
                if form.method == "get":
                    findings.append(
                        self.finding(
                            title=f"Поле пароля отправляется методом GET ({label})",
                            severity=Severity.HIGH,
                            description="Пароль попадёт в URL, логи сервера и историю браузера.",
                            remediation="Используйте метод POST для форм аутентификации.",
                            url=action_url,
                        )
                    )

        return findings


def _submits_over_http(action_url: str, page_is_https: bool) -> bool:
    scheme = urlparse(action_url).scheme.lower()
    if scheme == "http":
        return True
    # Relative action on an HTTP page also submits over HTTP.
    if scheme == "" and not page_is_https:
        return True
    return False
