"""logkit (Python) — structured JSON logs per our logging standard (AGENTS.md "Logging standard"). Stdlib only.
Canonical copy: /home/flori/tools/logkit (vendor this single file into an app).

    import logkit
    log = logkit.setup(app="jev-router")          # root logging -> JSON lines on stdout (uvicorn/gunicorn loggers too)
    app.add_middleware(logkit.ASGIMiddleware)      # FastAPI/Starlette: request id + one access line per request
    log.info("invoice.created", extra={"account_id": acc})     # fields via extra=; request_id is added automatically
    log.exception("stripe.webhook_failed")                       # error with stack
    with logkit.timed(log, "stripe.charge", account_id=acc): ...  # outbound call duration / failure

    class Handler(logkit.HTTPLogMixin, BaseHTTPRequestHandler): ...   # stdlib http.server apps

Every line: {"ts","level","app","msg","logger", ...fields}. Secrets redacted, e-mails / client IPs hashed here and again
in the central store (applogs). Never log request/response bodies, prompts or documents.
"""
from __future__ import annotations

import contextlib
import contextvars
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import sys
import time
import traceback
import uuid

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)
fields_var: contextvars.ContextVar[dict | None] = contextvars.ContextVar("log_fields", default=None)

REDACTED = "[REDACTED]"
_SALT = (os.environ.get("LOG_HASH_SALT") or secrets.token_hex(16)).encode()
OWN_IPS = {"65.109.49.103", "65.108.15.165", "37.27.102.32"}
SENSITIVE_KEY = re.compile(
    r"(?i)^(?:x-)?(?:api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|token|secret|"
    r"client[_-]?secret|password|passwd|pwd|pass|authorization|proxy-authorization|cookie|set-cookie|session|sessionid|"
    r"session[_-]?token|private[_-]?key|signature|sig|otp|pin|cvc|card[_-]?number|iban|stripe[_-]?signature|webhook[_-]?secret)$")
IP_KEY = re.compile(r"(?i)^(?:ip|client[_-]?ip|remote[_-]?ip|remote[_-]?addr(?:ess)?|x-forwarded-for|x-real-ip|"
                    r"cf-connecting-ip|source[_-]?ip|user[_-]?ip)$")
_TOKENS = [
    (re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{12,}"), lambda m: f"{m.group(1)} {REDACTED}"),
    (re.compile(r"\bsk-(?:ant-|proj-|or-v1-)?[A-Za-z0-9_-]{16,}"), REDACTED),
    (re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}"), REDACTED),
    (re.compile(r"\bwhsec_[A-Za-z0-9]{10,}"), REDACTED),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"), REDACTED),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), REDACTED),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), REDACTED),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), REDACTED),
    (re.compile(r"\bcpk_[A-Za-z0-9._-]{16,}"), REDACTED),
    (re.compile(r"\bhf_[A-Za-z0-9]{30,}"), REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), REDACTED),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"), REDACTED),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@"), lambda m: f"{m.group(1)}{m.group(2)}:{REDACTED}@"),
    (re.compile(r"(?i)([\"']?\b(?:api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|auth[_-]?token|token|secret|"
                r"client[_-]?secret|password|passwd|pwd|authorization|cookie|session[_-]?id|session[_-]?token|x-api-key|"
                r"private[_-]?key)[\"']?\s*[:=]\s*)([\"']?)(?!\d+\b)(?!\[REDACTED\])([^\s\"'&,;}{]{4,})"),
     lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}"),
    (re.compile(r"(?i)([?&](?:key|api_key|apikey|token|access_token|auth|sig|signature|password|code|secret)=)[^&\s\"'#]+"),
     lambda m: m.group(1) + REDACTED),
]
_EMAIL = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]{1,64})@((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})\b")
_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_RID_OK = re.compile(r"^[A-Za-z0-9._:-]{6,128}$")
_STD_ATTRS = set(vars(logging.makeLogRecord({}))) | {"message", "asctime", "taskName", "color_message"}


def hash_id(value, kind: str = "id"):
    if value in (None, ""):
        return value
    return f"{kind}~{hmac.new(_SALT, str(value).strip().lower().encode(), hashlib.sha256).hexdigest()[:12]}"


def _private(ip: str) -> bool:
    if ip in OWN_IPS:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True  # not an IP: leave alone
    return a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified or a.is_reserved


def hash_ip(ip):
    if not ip:
        return None
    ip = str(ip).strip()
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    return ip if _private(ip) else hash_id(ip, "ip")


def scrub_text(s: str) -> str:
    if not isinstance(s, str) or not s:
        return s
    for pat, rep in _TOKENS:
        s = pat.sub(rep, s)
    s = _EMAIL.sub(lambda m: f"{hash_id(m.group(0), 'email')}@{m.group(2)}", s)
    if "." in s:
        s = _IPV4.sub(lambda m: m.group(0) if _private(m.group(0)) else hash_id(m.group(0), "ip"), s)
    return s


def scrub(v, depth: int = 0):
    if depth > 8:
        return "[DEPTH]"
    if isinstance(v, str):
        return scrub_text(v if len(v) <= 8192 else v[:8192] + "…[truncated]")
    if isinstance(v, (int, float, bool)) or v is None:
        return v
    if isinstance(v, BaseException):
        return {"name": type(v).__name__, "message": scrub_text(str(v))}
    if isinstance(v, (bytes, bytearray)):
        return f"[bytes {len(v)}]"
    if isinstance(v, dict):
        out = {}
        for k, val in v.items():
            ks = str(k)
            if SENSITIVE_KEY.match(ks) and val not in (None, "") and not isinstance(val, (bool, int, float)):
                out[ks] = REDACTED
            elif IP_KEY.match(ks) and isinstance(val, str):
                out[ks] = ", ".join(hash_ip(x) or "" for x in val.split(","))
            else:
                out[ks] = scrub(val, depth + 1)
        return out
    if isinstance(v, (list, tuple, set)):
        return [scrub(x, depth + 1) for x in list(v)[:100]]
    return scrub_text(str(v))


class JsonFormatter(logging.Formatter):
    def __init__(self, app: str):
        super().__init__()
        self.app = app

    def format(self, record: logging.LogRecord) -> str:
        try:
            lvl = record.levelname.lower()
            rec = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
                "level": {"warning": "warn", "critical": "fatal"}.get(lvl, lvl),
                "app": self.app,
                "msg": scrub_text(record.getMessage()),
                "logger": record.name,
            }
            rid = request_id_var.get()
            if rid:
                rec["request_id"] = rid
            extra_ctx = fields_var.get()
            if extra_ctx:
                rec.update(scrub(extra_ctx))
            for k, v in record.__dict__.items():
                if k not in _STD_ATTRS and not k.startswith("_") and v is not None:
                    rec[k] = scrub(v) if not (SENSITIVE_KEY.match(k) and v not in (None, "")) else REDACTED
            if record.exc_info and record.exc_info[0] is not None:
                et, ev, tb = record.exc_info
                rec["err"] = {"name": et.__name__, "message": scrub_text(str(ev)),
                              "stack": scrub_text("".join(traceback.format_exception(et, ev, tb))[-6000:])}
            return json.dumps(rec, default=str, ensure_ascii=False)
        except Exception as e:  # never raise from logging
            return json.dumps({"level": "error", "app": self.app, "msg": "logkit.format_failed", "error": str(e)})


def setup(app: str | None = None, level: str | None = None, quiet_access: bool = True) -> logging.Logger:
    """Configure root logging to JSON on stdout. Idempotent. Returns the app logger."""
    app = app or os.environ.get("LOG_APP") or os.environ.get("COOLIFY_RESOURCE_NAME") or "app"
    lvl = getattr(logging, (level or os.environ.get("LOG_LEVEL", "INFO")).upper(), logging.INFO)
    root = logging.getLogger()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(app))
    handler._logkit = True  # type: ignore[attr-defined]
    root.handlers = [h for h in root.handlers if getattr(h, "_logkit", False)] or [handler]
    root.setLevel(lvl)
    for name in ("uvicorn", "uvicorn.error", "gunicorn", "gunicorn.error", "aiohttp", "httpx"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True
    if quiet_access:  # replaced by the middleware's structured access line
        for name in ("uvicorn.access", "gunicorn.access"):
            lg = logging.getLogger(name)
            lg.handlers = []
            lg.propagate = False
            lg.disabled = True
    logging.getLogger("httpx").setLevel(max(lvl, logging.WARNING))
    log = logging.getLogger(app)

    def _excepthook(et, ev, tb):
        log.critical("process.crash", exc_info=(et, ev, tb))
        sys.__excepthook__(et, ev, tb)
    sys.excepthook = _excepthook
    log.info("process.start", extra={"python": sys.version.split()[0], "pid": os.getpid(),
                                      "commit": os.environ.get("SOURCE_COMMIT") or None})
    return log


def bind(**fields) -> None:
    """Add fields (e.g. account_id=...) to every log line of the current request/task."""
    cur = dict(fields_var.get() or {})
    cur.update(fields)
    fields_var.set(cur)


def _clean_rid(v):
    return v if v and _RID_OK.match(v) else uuid.uuid4().hex


_SKIP = re.compile(r"^/(?:healthz?|readyz|livez|api/health|_health|favicon\.ico)(?:$|/)")


class ASGIMiddleware:
    """Pure ASGI middleware (FastAPI/Starlette/any ASGI). Request id in/out (X-Request-Id), one access line per
    request (method, path without query, route, status, duration_ms, ip_hash, ua), unhandled errors with stack.
    Behaviour unchanged: exceptions are re-raised."""

    def __init__(self, app, logger: logging.Logger | None = None, skip=_SKIP, ip: bool = True, ua: bool = True, path_mask=None):
        # ip/ua=False: leave ip_hash / user agent out (when the app's privacy page promises no IPs/UAs in logs)
        self.app = app
        self.ip, self.ua = ip, ua
        self.path_mask = path_mask  # callable(path)->path: replace secrets in URL paths (tokens, page ids)
        self.log = logger or logging.getLogger(os.environ.get("LOG_APP") or "app")
        self.skip = skip

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}
        rid = _clean_rid(headers.get("x-request-id"))
        tok = request_id_var.set(rid)
        ftok = fields_var.set({})
        scope.setdefault("state", {})["request_id"] = rid
        t0 = time.perf_counter()
        status = {"code": 500, "bytes": 0}

        async def _send(msg):
            if msg["type"] == "http.response.start":
                status["code"] = msg["status"]
                hs = list(msg.get("headers") or [])
                if not any(k.lower() == b"x-request-id" for k, _ in hs):
                    hs.append((b"x-request-id", rid.encode()))
                msg = {**msg, "headers": hs}
            elif msg["type"] == "http.response.body":
                status["bytes"] += len(msg.get("body") or b"")
            await send(msg)

        err = None
        try:
            await self.app(scope, receive, _send)
        except BaseException as e:  # noqa: BLE001
            err = e
            raise
        finally:
            path = scope.get("path", "")
            code = status["code"]
            if not (code < 400 and err is None and self.skip and self.skip.match(path)):
                route = scope.get("route")
                client = scope.get("client") or (None, None)
                ip = (headers.get("x-forwarded-for") or "").split(",")[0].strip() or client[0]
                fields = {"method": scope.get("method"), "path": (self.path_mask(path) if self.path_mask else path)[:300],
                          "route": getattr(route, "path", None), "status": code,
                          "duration_ms": round((time.perf_counter() - t0) * 1000, 1), "bytes": status["bytes"],
                          "ip_hash": hash_ip(ip) if self.ip else None,
                          "ua": ((headers.get("user-agent") or "")[:160] or None) if self.ua else None}
                lvl = logging.ERROR if code >= 500 or err else logging.WARNING if code >= 400 else logging.INFO
                self.log.log(lvl, "http.request", extra=fields, exc_info=(type(err), err, err.__traceback__) if err else None)
            request_id_var.reset(tok)
            fields_var.reset(ftok)


class HTTPLogMixin:
    """For http.server.BaseHTTPRequestHandler subclasses: put it FIRST in the bases.
    Adds request ids (X-Request-Id), one JSON access line per request, and routes log_message/log_error to logging."""
    logkit_logger: logging.Logger | None = None
    logkit_ip = True   # False: no ip_hash in access lines (privacy page promises no IPs in logs)
    logkit_ua = True
    logkit_path_mask = None  # staticmethod(callable(path)->path) when URL paths carry secrets (tokens, page ids)

    def _lk_log(self):
        return self.logkit_logger or logging.getLogger(os.environ.get("LOG_APP") or "app")

    def parse_request(self):  # type: ignore[override]
        self._lk_t0 = time.perf_counter()
        ok = super().parse_request()  # type: ignore[misc]
        rid = _clean_rid(self.headers.get("X-Request-Id") if ok and self.headers else None)
        self.request_id = rid
        request_id_var.set(rid)
        fields_var.set({})
        return ok

    def end_headers(self):  # type: ignore[override]
        rid = getattr(self, "request_id", None)
        if rid and not getattr(self, "_lk_rid_sent", False):
            self._lk_rid_sent = True
            self.send_header("X-Request-Id", rid)
        super().end_headers()  # type: ignore[misc]

    def log_request(self, code="-", size="-"):  # type: ignore[override]
        try:
            code_i = int(getattr(code, "value", code))
        except (TypeError, ValueError):
            code_i = 0
        path = (getattr(self, "path", "") or "").split("?")[0]
        if code_i < 400 and _SKIP.match(path):
            return
        if self.logkit_path_mask:
            path = self.logkit_path_mask(path)
        path = path[:300]
        ip = ((self.headers.get("X-Forwarded-For") if getattr(self, "headers", None) else None) or "").split(",")[0].strip() \
            or self.client_address[0]
        t0 = getattr(self, "_lk_t0", None)
        fields = {"method": getattr(self, "command", None), "path": path, "status": code_i,
                  "duration_ms": round((time.perf_counter() - t0) * 1000, 1) if t0 else None,
                  "bytes": int(size) if str(size).isdigit() else None, "ip_hash": hash_ip(ip) if self.logkit_ip else None,
                  "ua": (((self.headers.get("User-Agent") if getattr(self, "headers", None) else None) or "")[:160] or None)
                  if self.logkit_ua else None}
        lvl = logging.ERROR if code_i >= 500 else logging.WARNING if code_i >= 400 else logging.INFO
        self._lk_log().log(lvl, "http.request", extra=fields)
        self._lk_rid_sent = False

    def log_error(self, format, *args):  # noqa: A002
        # http.server's own error lines can quote the raw request line (with secrets in the path): keep only the code
        self._lk_log().warning("http.error", extra={"detail": str(args[0]) if args else None} if not self.logkit_path_mask else None)

    def log_message(self, format, *args):  # noqa: A002
        if not self.logkit_path_mask:
            self._lk_log().info(format % args)


@contextlib.contextmanager
def timed(log: logging.Logger, call: str, **fields):
    """Log an outbound call's duration; failures logged with stack and re-raised."""
    t0 = time.perf_counter()
    try:
        yield
    except Exception:
        log.exception("external.call_failed", extra={"call": call, "duration_ms": round((time.perf_counter() - t0) * 1000, 1), **fields})
        raise
    log.info("external.call", extra={"call": call, "duration_ms": round((time.perf_counter() - t0) * 1000, 1), **fields})
