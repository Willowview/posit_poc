import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from password_hash import verify_password


ROOT = Path(__file__).resolve().parent
PUBLIC_DIR = ROOT / "public"
SESSION_TTL_SECONDS = 10 * 60
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_MAX_ATTEMPTS = 5
SESSION_COOKIE = "poc_editor_session"

app = FastAPI(title="Connect Cloud Static + API Proof of Concept")
sessions = {}
login_attempts = {}


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class SignBody(BaseModel):
    message: str = Field(min_length=1, max_length=500)


def editor_settings():
    username = os.environ.get("EDITOR_USERNAME", "")
    encoded_hash = os.environ.get("EDITOR_PASSWORD_HASH", "")
    if not username or not encoded_hash:
        raise HTTPException(
            status_code=503,
            detail="Editor login is not configured for this deployment.",
        )
    return username, encoded_hash


def require_same_origin(request):
    origin = request.headers.get("origin")
    host = request.headers.get("host", "")
    if not origin or urlsplit(origin).netloc.lower() != host.lower():
        raise HTTPException(status_code=403, detail="Request origin is not allowed.")


def client_key(request):
    return request.client.host if request.client else "unknown"


def enforce_login_limit(request):
    now = time.time()
    key = client_key(request)
    attempt = login_attempts.get(key)
    if attempt and attempt["until"] <= now:
        login_attempts.pop(key, None)
        attempt = None
    if attempt and attempt["count"] >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail="Too many sign-in attempts. Try again later.",
        )
    return key


def record_login_failure(key):
    now = time.time()
    attempt = login_attempts.get(key)
    count = attempt["count"] + 1 if attempt and attempt["until"] > now else 1
    login_attempts[key] = {"count": count, "until": now + LOGIN_WINDOW_SECONDS}


def current_session(request, response=None, refresh=True):
    token = request.cookies.get(SESSION_COOKIE, "")
    session = sessions.get(token)
    if not session:
        return None
    now = time.time()
    if session["expires_at"] <= now:
        sessions.pop(token, None)
        return None
    if refresh:
        session["expires_at"] = now + SESSION_TTL_SECONDS
        if response:
            set_session_cookie(response, token)
    return session


def require_editor(request, response):
    require_same_origin(request)
    session = current_session(request, response)
    if not session:
        raise HTTPException(status_code=401, detail="Editor sign-in is required.")
    csrf = request.headers.get("x-csrf-token", "")
    if not hmac.compare_digest(csrf, session["csrf"]):
        raise HTTPException(status_code=403, detail="Request verification failed.")
    return session


def set_session_cookie(response, token):
    secure = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(PUBLIC_DIR / "index.html")


@app.get("/api/public")
def public_status(request: Request, response: Response):
    session = current_session(request, response)
    return {
        "message": "The static page and API are served by one Connect Cloud app.",
        "authenticated": bool(session),
        "role": "editor" if session else "reader",
    }


@app.get("/api/session")
def session_status(request: Request, response: Response):
    session = current_session(request, response)
    if not session:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "username": session["username"],
        "csrf_token": session["csrf"],
    }


@app.post("/api/login")
def login(body: LoginBody, request: Request, response: Response):
    require_same_origin(request)
    attempt_key = enforce_login_limit(request)
    expected_username, expected_hash = editor_settings()
    username_matches = hmac.compare_digest(
        body.username.encode("utf-8"), expected_username.encode("utf-8")
    )
    password_matches = verify_password(body.password, expected_hash)
    if not username_matches or not password_matches:
        record_login_failure(attempt_key)
        raise HTTPException(status_code=401, detail="Username or password is incorrect.")

    login_attempts.pop(attempt_key, None)
    token = secrets.token_urlsafe(32)
    session = {
        "username": expected_username,
        "csrf": secrets.token_urlsafe(32),
        "expires_at": time.time() + SESSION_TTL_SECONDS,
    }
    sessions[token] = session
    set_session_cookie(response, token)
    return {
        "authenticated": True,
        "username": session["username"],
        "csrf_token": session["csrf"],
    }


@app.post("/api/logout")
def logout(request: Request, response: Response):
    session = require_editor(request, response)
    token = request.cookies.get(SESSION_COOKIE, "")
    sessions.pop(token, None)
    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
        samesite="strict",
    )
    return {"authenticated": False, "username": session["username"]}


@app.post("/api/sign")
def sign_message(body: SignBody, request: Request, response: Response):
    require_editor(request, response)
    secret = os.environ.get("DEMO_HMAC_SECRET", "")
    if not secret:
        raise HTTPException(
            status_code=503,
            detail="The server-side demo secret is not configured.",
        )
    signature = hmac.new(
        secret.encode("utf-8"), body.message.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return {"signature": signature, "secret_returned_to_browser": False}
