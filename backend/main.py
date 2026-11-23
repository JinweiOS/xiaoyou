"""Single-process, in-memory daily access-code authentication."""
import asyncio
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta
import hmac
import os
from pathlib import Path
import secrets
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from .notifications import WebhookNotifier

ROOT = Path(__file__).resolve().parent.parent
TZ = ZoneInfo('Asia/Shanghai')
COOKIE = 'alumni_session'


class VerifyBody(BaseModel):
    code: str = Field(pattern=r'^[0-9]{6}$', min_length=6, max_length=6)


class AuthState:
    def __init__(self, now=None, on_rotate=None):
        self.now = now or (lambda: datetime.now(TZ))
        self.on_rotate = on_rotate
        self.code = ''
        self.generated_at = None
        self.expires_at = None
        self.sessions = set()
        self.failures = {}
        self.refresh()

    def refresh(self, *, force=False):
        current = self.now().astimezone(TZ)
        if not force and self.expires_at is not None and current < self.expires_at:
            return
        previous = self.code
        while not self.code or self.code == previous:
            self.code = f'{secrets.randbelow(1000000):06d}'
        self.generated_at = current
        boundary = current.replace(hour=9, minute=0, second=0, microsecond=0)
        self.expires_at = boundary if current < boundary else boundary + timedelta(days=1)
        self.sessions.clear()
        self.failures.clear()
        if self.on_rotate:
            self.on_rotate(self.code, self.generated_at, self.expires_at)

    async def schedule(self):
        while True:
            self.refresh()
            delay = (self.expires_at - self.now().astimezone(TZ)).total_seconds()
            # Recheck periodically so clock changes and resume from sleep recover.
            await asyncio.sleep(max(.05, min(delay, 60)))

    def authenticated(self, request):
        self.refresh()
        return request.cookies.get(COOKIE) in self.sessions

    def throttle(self, key):
        now = self.now().timestamp()
        self.failures = {ip: record for ip, record in self.failures.items() if record[1] > now}
        count, until = self.failures.get(key, (0, now + 60))
        if count >= 5:
            raise HTTPException(429, 'Too many attempts', headers={'Retry-After': str(max(1, int(until-now)))})
        return count, until


def create_app(admin_token=None, now=None, secure_cookie=None, webhook_url=None, webhook_sender=None):
    token = admin_token if admin_token is not None else os.getenv('AUTH_ADMIN_TOKEN', '')
    secure = secure_cookie if secure_cookie is not None else os.getenv('COOKIE_SECURE', 'false').lower() == 'true'
    webhook = webhook_url if webhook_url is not None else os.getenv('WECHAT_WEBHOOK_URL', '')

    @asynccontextmanager
    async def lifespan(app):
        if len(token) < 32:
            raise RuntimeError('Set AUTH_ADMIN_TOKEN to a secret of at least 32 characters before starting.')
        app.state.notifier = WebhookNotifier(webhook, sender=webhook_sender)
        app.state.auth = AuthState(now, on_rotate=app.state.notifier.enqueue)
        notification_task = asyncio.create_task(app.state.notifier.run())
        task = asyncio.create_task(app.state.auth.schedule())
        try:
            yield
        finally:
            task.cancel()
            notification_task.cancel()
            with suppress(asyncio.CancelledError):
                await task
            with suppress(asyncio.CancelledError):
                await notification_task
            app.state.auth.sessions.clear()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware('http')
    async def no_cache(request, call_next):
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'same-origin'
        return response

    @app.get('/')
    @app.get('/index.html')
    async def entrance():
        return FileResponse(ROOT / 'index.html')

    def require_admin(request: Request):
        authorization = request.headers.get('authorization', '')
        if not hmac.compare_digest(authorization.encode(), ('Bearer ' + token).encode()):
            raise HTTPException(401, 'Administrator credentials required')

    def code_payload(state):
        return {'code': state.code, 'generated_at': state.generated_at.isoformat(),
                'expires_at': state.expires_at.isoformat(), 'timezone': 'Asia/Shanghai',
                'notification': app.state.notifier.status.copy()}

    @app.get('/api/auth/code')
    async def current_code(request: Request):
        require_admin(request)
        state = app.state.auth
        state.refresh()
        return code_payload(state)

    @app.post('/api/auth/code/refresh')
    async def refresh_code(request: Request):
        require_admin(request)
        state = app.state.auth
        state.refresh(force=True)
        return code_payload(state)

    @app.post('/api/auth/code/notify')
    async def notify_current_code(request: Request):
        require_admin(request)
        state = app.state.auth
        state.refresh()
        app.state.notifier.enqueue(state.code, state.generated_at, state.expires_at, resend=True)
        return code_payload(state)

    @app.post('/api/auth/verify')
    async def verify(body: VerifyBody, request: Request):
        state = app.state.auth
        state.refresh()
        ip = request.client.host if request.client else 'unknown'
        count, until = state.throttle(ip)
        if not hmac.compare_digest(body.code, state.code):
            state.failures[ip] = (count + 1, until)
            raise HTTPException(401, 'Invalid or expired code')
        state.failures.pop(ip, None)
        old = request.cookies.get(COOKIE)
        state.sessions.discard(old)
        session = secrets.token_urlsafe(32)
        state.sessions.add(session)
        response = JSONResponse({'ok': True, 'expires_at': state.expires_at.isoformat()})
        response.set_cookie(COOKIE, session, httponly=True, secure=secure, samesite='strict',
                            path='/', max_age=max(1, int((state.expires_at-state.now().astimezone(TZ)).total_seconds())))
        return response

    @app.get('/api/auth/session')
    async def session(request: Request):
        if not app.state.auth.authenticated(request):
            raise HTTPException(401, 'Authentication required')
        return {'authenticated': True, 'expires_at': app.state.auth.expires_at.isoformat()}

    @app.get('/app')
    async def application(request: Request):
        if not app.state.auth.authenticated(request):
            return RedirectResponse('/', status_code=303)
        return FileResponse(ROOT / 'private' / 'app.html')

    @app.get('/assets/{asset_path:path}')
    async def asset(asset_path: str, request: Request):
        if not app.state.auth.authenticated(request):
            raise HTTPException(401, 'Authentication required')
        base = (ROOT / 'assets').resolve()
        target = (base / asset_path).resolve()
        if not target.is_relative_to(base) or target.suffix.lower() not in {'.png', '.jpg', '.jpeg', '.svg', '.webp', '.gif'} or not target.is_file():
            raise HTTPException(404, 'Not found')
        return FileResponse(target)

    return app


app = create_app()
