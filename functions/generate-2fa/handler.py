import json
import base64
import os
import secrets
import psycopg2
import pyotp
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

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        if not user:
            cur.close()
            conn.close()
            return {
                "statusCode": 404,
                "body": json.dumps({"error": "User not found"}),
            }

        # Generate TOTP secret
        totp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(totp_secret)
        provisioning_uri = totp.provisioning_uri(name=username, issuer_name="COFRAP")

        # Store base64-encoded secret
        secret_b64 = base64.b64encode(totp_secret.encode()).decode()
        gendate = int(datetime.utcnow().timestamp())

        cur.execute(
            "UPDATE users SET mfa = %s, gendate = %s, expired = 0 WHERE username = %s",
            (secret_b64, gendate, username),
        )
        conn.commit()
        cur.close()
        conn.close()

        qr_code_b64 = generate_qr_code(provisioning_uri)

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "username": username,
                    "totp_secret": totp_secret,
                    "provisioning_uri": provisioning_uri,
                    "qr_code": qr_code_b64,
                    "message": "2FA secret generated and stored successfully",
                }
            ),
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }
