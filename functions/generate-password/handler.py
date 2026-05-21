import json
import secrets
import string
import base64
import os
import psycopg2
import qrcode
import io
from datetime import datetime


def get_db_connection():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "postgres-service"),
        port=os.environ.get("DB_PORT", "5432"),
        database=os.environ.get("DB_NAME", "cofrap"),
        user=os.environ.get("DB_USER", "cofrap"),
        password=os.environ.get("DB_PASSWORD", "cofrap"),
    )


def generate_password(length=24):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        if has_upper and has_lower and has_digit and has_special:
            return password


def generate_qr_code(data: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("utf-8")


def handle(event, context):
    try:
        body = json.loads(event.body) if isinstance(event.body, str) else event.body
        username = body.get("username")
        if not username:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "username is required"}),
            }

        password = generate_password(24)
        password_b64 = base64.b64encode(password.encode()).decode()
        qr_data = f"cofrap:password:{username}:{password}"
        qr_code_b64 = generate_qr_code(qr_data)
        gendate = int(datetime.utcnow().timestamp())

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        existing = cur.fetchone()

        if existing:
            cur.execute(
                "UPDATE users SET password = %s, gendate = %s, expired = 0 WHERE username = %s",
                (password_b64, gendate, username),
            )
        else:
            cur.execute(
                "INSERT INTO users (username, password, gendate, expired) VALUES (%s, %s, %s, 0)",
                (username, password_b64, gendate),
            )

        conn.commit()
        cur.close()
        conn.close()

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "username": username,
                    "password": password,
                    "qr_code": qr_code_b64,
                    "message": "Password generated and stored successfully",
                }
            ),
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }
