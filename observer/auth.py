"""Single-owner password verification and short-lived browser sessions."""

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from pathlib import Path


SESSION_LIFETIME_SECONDS = 8 * 60 * 60
COOKIE_NAME = "__Host-lab_observer"


class OwnerLogin:
    def __init__(self, auth_file):
        path = Path(auth_file)
        if path.stat().st_mode & 0o077:
            raise ValueError("The authentication file must be private to its owner")
        stored = json.loads(path.read_text(encoding="utf-8"))
        self.salt = base64.b64decode(stored["salt"], validate=True)
        self.digest = base64.b64decode(stored["digest"], validate=True)
        self.sessions = {}
        self.lock = threading.Lock()

    def password_matches(self, password):
        candidate = hashlib.scrypt(password.encode(), salt=self.salt, n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(candidate, self.digest)

    def new_session(self):
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).digest()
        with self.lock:
            self.sessions[digest] = time.time() + SESSION_LIFETIME_SECONDS
        return token

    def session_valid(self, token):
        if not token:
            return False
        digest = hashlib.sha256(token.encode()).digest()
        with self.lock:
            expiry = self.sessions.get(digest, 0)
            if expiry <= time.time():
                self.sessions.pop(digest, None)
                return False
            return True

    def end_session(self, token):
        if not token:
            return
        digest = hashlib.sha256(token.encode()).digest()
        with self.lock:
            self.sessions.pop(digest, None)
