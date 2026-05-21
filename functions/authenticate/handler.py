import json
import base64
import os
import psycopg2
import pyotp
from datetime import datetime, timezone


def get_db_connection():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "postgres-service"),
        port=os.environ.get("DB_PORT", "5432"),
        database=os.environ.get("DB_NAME", "cofrap"),
        user=os.environ.get("DB_USER", "cofrap"),
        password=os.environ.get("DB_PASSWORD", "cofrap"),
    )

# test wf    

SIX_MONTHS_SECONDS = 6 * 30 * 24 * 3600


def handle(event, context):
    try:
        body = json.loads(event.body) if isinstance(event.body, str) else event.body
        username = body.get("username")
        password = body.get("password")
        totp_code = body.get("totp_code")

        if not username or not password or not totp_code:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "username, password and totp_code are required"}),
            }

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, password, mfa, gendate, expired FROM users WHERE username = %s",
            (username,),
        )
        user = cur.fetchone()

        if not user:
            cur.close()
            conn.close()
            return {
                "statusCode": 401,
                "body": json.dumps({"error": "Invalid credentials"}),
            }

        user_id, stored_password_b64, stored_mfa_b64, gendate, expired = user

        # Check if already expired
        if expired == 1:
            cur.close()
            conn.close()
            return {
                "statusCode": 403,
                "body": json.dumps({
                    "error": "Account expired",
                    "action": "renew",
                    "message": "Your credentials have expired. Please renew your password and 2FA.",
                }),
            }

        # Verify password
        password_b64 = base64.b64encode(password.encode()).decode()
        if password_b64 != stored_password_b64:
            cur.close()
            conn.close()
            return {
                "statusCode": 401,
                "body": json.dumps({"error": "Invalid credentials"}),
            }

        # Verify TOTP
        if not stored_mfa_b64:
            cur.close()
            conn.close()
            return {
                "statusCode": 403,
                "body": json.dumps({
                    "error": "2FA not configured",
                    "action": "setup_2fa",
                    "message": "Please configure 2FA for your account.",
                }),
            }

        totp_secret = base64.b64decode(stored_mfa_b64).decode()
        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(totp_code, valid_window=1):
            cur.close()
            conn.close()
            return {
                "statusCode": 401,
                "body": json.dumps({"error": "Invalid 2FA code"}),
            }

        # Check credentials age (6 months)
        now = int(datetime.now(timezone.utc).timestamp())
        if gendate and (now - gendate) > SIX_MONTHS_SECONDS:
            cur.execute(
                "UPDATE users SET expired = 1 WHERE username = %s", (username,)
            )
            conn.commit()
            cur.close()
            conn.close()
            return {
                "statusCode": 403,
                "body": json.dumps({
                    "error": "Credentials expired (older than 6 months)",
                    "action": "renew",
                    "message": "Your credentials have expired. Please renew your password and 2FA.",
                }),
            }

        cur.close()
        conn.close()

        return {
            "statusCode": 200,
            "body": json.dumps({
                "success": True,
                "username": username,
                "message": "Authentication successful",
            }),
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }
