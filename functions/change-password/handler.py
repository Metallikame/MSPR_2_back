import json
import base64
import os
import string
import sys
import psycopg2
import pyotp
from datetime import datetime, timezone


def get_db_connection():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "postgres-service.cofrap.svc.cluster.local"),
        port=os.environ.get("DB_PORT", "5432"),
        database=os.environ.get("DB_NAME", "cofrap"),
        user=os.environ.get("DB_USER", "cofrap"),
        password=os.environ.get("DB_PASSWORD", "cofrap_secure_pwd_2024"),
    )


def is_strong_password(password):
    return (
        len(password) >= 12
        and any(c.isupper() for c in password)
        and any(c.islower() for c in password)
        and any(c.isdigit() for c in password)
        and any(c in string.punctuation for c in password)
    )


def handle(req):
    try:
        body = json.loads(req) if req.strip() else {}
        username = body.get("username")
        current_password = body.get("current_password")
        totp_code = body.get("totp_code")
        new_password = body.get("new_password")

        if not username or not current_password or not totp_code or not new_password:
            return json.dumps({
                "error": "username, current_password, totp_code and new_password are required"
            })

        if not is_strong_password(new_password):
            return json.dumps({
                "error": "new_password must be at least 12 characters and include "
                         "uppercase, lowercase, digit and punctuation"
            })

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT password, mfa FROM users WHERE username = %s",
            (username,),
        )
        user = cur.fetchone()

        if not user:
            cur.close()
            conn.close()
            return json.dumps({"error": "Invalid credentials"})

        stored_password_b64, stored_mfa_b64 = user

        current_password_b64 = base64.b64encode(current_password.encode()).decode()
        if current_password_b64 != stored_password_b64:
            cur.close()
            conn.close()
            return json.dumps({"error": "Invalid credentials"})

        if not stored_mfa_b64:
            cur.close()
            conn.close()
            return json.dumps({
                "error": "2FA not configured",
                "action": "setup_2fa",
            })

        totp_secret = base64.b64decode(stored_mfa_b64).decode()
        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(totp_code, valid_window=1):
            cur.close()
            conn.close()
            return json.dumps({"error": "Invalid 2FA code"})

        if new_password == current_password:
            cur.close()
            conn.close()
            return json.dumps({"error": "new_password must be different from current_password"})

        new_password_b64 = base64.b64encode(new_password.encode()).decode()
        gendate = int(datetime.now(timezone.utc).timestamp())
        cur.execute(
            "UPDATE users SET password = %s, gendate = %s, expired = 0 WHERE username = %s",
            (new_password_b64, gendate, username),
        )
        conn.commit()
        cur.close()
        conn.close()

        return json.dumps({
            "success": True,
            "username": username,
            "message": "Password changed successfully",
        })

    except Exception as e:
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    input_data = sys.stdin.read()
    result = handle(input_data)
    print(result)
