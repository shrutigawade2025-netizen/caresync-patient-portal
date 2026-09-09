# auth_api.py
# CareSync Day 7 - Authentication and Authorisation Backend
#
# This file is the brain of the login system.
# It handles: register, login, logout, token refresh, and dashboards.
#
# Run this file with:
#   uvicorn auth_api:app --reload --port 8002
#
# Then open: http://127.0.0.1:8002/docs  to test all endpoints.

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta
import mysql.connector
import bcrypt
import re

# Create the FastAPI application
app = FastAPI(title="CareSync Auth API")

# This allows the HTML frontend (portal.html) to talk to this backend.
# Without this, the browser will block the request.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Token Settings ────────────────────────────────────────────────────────────
# SECRET_KEY is used to sign every token.
# Anyone who knows this key can create fake tokens, so keep it private.
SECRET_KEY            = "caresync-day7-secret-key-change-in-production"
ALGORITHM             = "HS256"
ACCESS_EXPIRE_MINUTES = 15  # Access token expires in 15 minutes
REFRESH_EXPIRE_DAYS   = 7   # Refresh token expires in 7 days

# This tells FastAPI to look for the token in the Authorization header.
# The client sends:  Authorization: Bearer <token>
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


# ── Database Connection ───────────────────────────────────────────────────────
# This function opens a connection to MySQL and returns it.
# We call this function inside every endpoint that needs the database.
def get_db():
    conn = mysql.connector.connect(
        host="localhost",
        port=3306,
        user="root",
        password="",
        database="caresync"
    )
    # dictionary=True means rows come back as {column: value} instead of tuples
    cur = conn.cursor(dictionary=True)
    return conn, cur


# ── Password Helpers ──────────────────────────────────────────────────────────
def hash_password(plain: str) -> str:
    # bcrypt scrambles the password so it cannot be read.
    # We store this scrambled version in the database, never the real password.
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain.encode(), salt).decode()

def verify_password(plain: str, hashed: str) -> bool:
    # At login time, bcrypt scrambles what the user typed
    # and compares it to the stored scrambled version.
    # Returns True if they match, False if not.
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ── Token Helpers ─────────────────────────────────────────────────────────────
def create_access_token(data: dict) -> str:
    # Short-lived token (15 minutes).
    # Sent on every API request to prove who the user is.
    # JWT standard requires the sub field to be a string.
    payload = data.copy()
    payload["sub"]  = str(data["sub"])
    payload["exp"]  = datetime.utcnow() + timedelta(minutes=ACCESS_EXPIRE_MINUTES)
    payload["type"] = "access"
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: dict) -> str:
    # Long-lived token (7 days).
    # Used only to get a new access token when the old one expires.
    # JWT standard requires the sub field to be a string.
    payload = data.copy()
    payload["sub"]  = str(data["sub"])
    payload["exp"]  = datetime.utcnow() + timedelta(days=REFRESH_EXPIRE_DAYS)
    payload["type"] = "refresh"
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def store_refresh_token(user_id: int, token: str):
    # Save the refresh token in the database.
    # When the user logs out, we delete this row.
    # If it is deleted, the user cannot get a new access token.
    conn, cur = get_db()
    expires = datetime.utcnow() + timedelta(days=REFRESH_EXPIRE_DAYS)
    cur.execute(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (%s, %s, %s)",
        (int(user_id), token, expires)
    )
    conn.commit()
    cur.close()
    conn.close()


# ── Password Strength Check ───────────────────────────────────────────────────
def is_strong_password(password: str) -> bool:
    # A good password must have all four of these:
    # 1. At least 8 characters
    # 2. At least one UPPERCASE letter
    # 3. At least one number
    # 4. At least one special character like @ # $ % ^ & + = !
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[@#$%^&+=!]", password):
        return False
    return True


# ── Request Models ────────────────────────────────────────────────────────────
# These classes define what data each endpoint expects from the client.

class RegisterRequest(BaseModel):
    email: str
    password: str
    role: str       # "doctor" or "patient"
    linked_id: int  # doctor_id or patient_id from the existing table

class LoginRequest(BaseModel):
    email: str
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str


# ── Reusable Dependency: get_current_user ─────────────────────────────────────
# This function runs automatically on every protected endpoint.
# It reads the token from the Authorization header,
# checks it is valid, and returns the logged-in user's details.
# If anything is wrong with the token, it immediately returns 401 Unauthorized.
def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode the token and read what is inside
        payload    = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # sub is stored as a string inside the token (JWT standard)
        # we convert it back to int to query the database
        user_id    = int(payload.get("sub"))
        token_type = payload.get("type")

        # Make sure it is an access token, not a refresh token
        if user_id is None or token_type != "access":
            raise credentials_error

    except (JWTError, TypeError, ValueError):
        raise credentials_error

    # Look up the user in the database using the user_id from the token
    conn, cur = get_db()
    cur.execute(
        "SELECT user_id, email, role, linked_id FROM users WHERE user_id = %s AND is_active = 1",
        (user_id,)
    )
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        raise credentials_error

    return user


# ── ENDPOINT: POST /register ──────────────────────────────────────────────────
@app.post("/register", status_code=201)
def register(req: RegisterRequest):
    # Step 1: Check if password is strong enough
    if not is_strong_password(req.password):
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters and include an uppercase letter, a number, and a special character (@#$%^&+=!)."
        )

    conn, cur = get_db()

    # Step 2: Check if this email is already registered
    cur.execute("SELECT user_id FROM users WHERE email = %s", (req.email,))
    if cur.fetchone():
        cur.close()
        conn.close()
        raise HTTPException(status_code=409, detail="Email already registered.")

    # Step 3: Hash the password and save the new user
    hashed = hash_password(req.password)
    cur.execute(
        "INSERT INTO users (email, password_hash, role, linked_id) VALUES (%s, %s, %s, %s)",
        (req.email, hashed, req.role, req.linked_id)
    )
    conn.commit()
    new_id = cur.lastrowid
    cur.close()
    conn.close()

    return {"message": "Account created.", "user_id": new_id}


# ── ENDPOINT: POST /login ─────────────────────────────────────────────────────
@app.post("/login")
def login(req: LoginRequest):
    conn, cur = get_db()
    cur.execute(
        "SELECT user_id, email, password_hash, role, linked_id FROM users WHERE email = %s AND is_active = 1",
        (req.email,)
    )
    user = cur.fetchone()
    cur.close()
    conn.close()

    # IMPORTANT SECURITY RULE:
    # We return the same error message whether the email does not exist
    # OR the password is wrong.
    # If the messages were different, an attacker could discover valid emails.
    INVALID_MSG = "Invalid email or password."

    if not user:
        raise HTTPException(status_code=401, detail=INVALID_MSG)

    if not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail=INVALID_MSG)

    # Build the token payload.
    # sub is the standard JWT claim for the user identifier.
    token_data    = {"sub": user["user_id"], "role": user["role"]}
    access_token  = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    # Save the refresh token in the database so logout can delete it
    store_refresh_token(user["user_id"], refresh_token)

    return {
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "token_type":    "bearer",
        "role":          user["role"],
        "linked_id":     user["linked_id"]
    }


# ── ENDPOINT: POST /refresh ───────────────────────────────────────────────────
@app.post("/refresh")
def refresh_token_endpoint(req: RefreshRequest):
    # When the access token expires (after 15 minutes),
    # the frontend sends the refresh token here to get a new access token.
    credentials_error = HTTPException(
        status_code=401,
        detail="Invalid or expired refresh token."
    )

    try:
        payload    = jwt.decode(req.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id    = int(payload.get("sub"))
        token_type = payload.get("type")
        if user_id is None or token_type != "refresh":
            raise credentials_error
    except (JWTError, TypeError, ValueError):
        raise credentials_error

    # Check the refresh token exists in the database
    conn, cur = get_db()
    cur.execute(
        "SELECT token_id FROM refresh_tokens WHERE token_hash = %s AND user_id = %s",
        (req.refresh_token, user_id)
    )
    record = cur.fetchone()

    if not record:
        cur.close()
        conn.close()
        raise credentials_error

    # Delete the old refresh token and issue a brand new one.
    # This is called token rotation. Each refresh gives you a fresh token.
    cur.execute(
        "DELETE FROM refresh_tokens WHERE token_hash = %s",
        (req.refresh_token,)
    )
    conn.commit()
    cur.close()
    conn.close()

    token_data   = {"sub": user_id, "role": payload.get("role")}
    access_token = create_access_token(token_data)
    new_refresh  = create_refresh_token(token_data)
    store_refresh_token(user_id, new_refresh)

    return {
        "access_token":  access_token,
        "refresh_token": new_refresh,
        "token_type":    "bearer"
    }


# ── ENDPOINT: POST /logout ────────────────────────────────────────────────────
@app.post("/logout")
def logout(req: RefreshRequest):
    # Delete the refresh token from the database.
    # After this, the user cannot get a new access token.
    # The browser will also delete the tokens on its side.
    conn, cur = get_db()
    cur.execute(
        "DELETE FROM refresh_tokens WHERE token_hash = %s",
        (req.refresh_token,)
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "Logged out."}


# ── ENDPOINT: GET /me ─────────────────────────────────────────────────────────
@app.get("/me")
def me(current_user: dict = Depends(get_current_user)):
    # Depends(get_current_user) runs the get_current_user function automatically.
    # If the token is valid, current_user contains the logged-in user's details.
    # If not, the request is blocked before it even reaches this line.
    return {
        "user_id":   current_user["user_id"],
        "email":     current_user["email"],
        "role":      current_user["role"],
        "linked_id": current_user["linked_id"]
    }


# ── ENDPOINT: GET /dashboard/doctor ──────────────────────────────────────────
@app.get("/dashboard/doctor")
def doctor_dashboard(current_user: dict = Depends(get_current_user)):
    # LEVEL 1 CHECK: Is this user a doctor?
    # If not, block immediately. A patient cannot reach this endpoint.
    if current_user["role"] != "doctor":
        raise HTTPException(status_code=403, detail="Access denied. Doctors only.")

    doctor_id = current_user["linked_id"]
    conn, cur = get_db()

    # LEVEL 2 CHECK: WHERE clause filters by this doctor's ID only.
    # No date filter so past and future appointments are always visible.
    # Shows the 10 most recent appointments for this doctor.
    cur.execute("""
        SELECT
            a.appointment_id,
            p.full_name        AS patient_name,
            p.blood_group,
            p.phone            AS phone_number,
            a.appointment_date,
            a.appointment_time,
            a.status,
            a.reason
        FROM appointment a
        JOIN patient p ON p.patient_id = a.patient_id
        WHERE a.doctor_id = %s
        ORDER BY a.appointment_date DESC
        LIMIT 10
    """, (doctor_id,))

    appointments = cur.fetchall()

    # Convert date and time objects to strings so they can be sent as JSON
    for appt in appointments:
        if appt["appointment_date"]:
            appt["appointment_date"] = str(appt["appointment_date"])
        if appt["appointment_time"]:
            appt["appointment_time"] = str(appt["appointment_time"])

    cur.close()
    conn.close()

    return {
        "doctor_id":          doctor_id,
        "today_appointments": appointments
    }


# ── ENDPOINT: GET /dashboard/patient ─────────────────────────────────────────
@app.get("/dashboard/patient")
def patient_dashboard(current_user: dict = Depends(get_current_user)):
    # LEVEL 1 CHECK: Is this user a patient?
    if current_user["role"] != "patient":
        raise HTTPException(status_code=403, detail="Access denied. Patients only.")

    patient_id = current_user["linked_id"]
    conn, cur  = get_db()

    # LEVEL 2 CHECK: Every query filters by this patient's ID only.
    # Shows the 10 most recent appointments regardless of date.
    cur.execute("""
        SELECT
            a.appointment_id,
            a.appointment_date,
            a.appointment_time,
            a.status,
            a.reason,
            d.full_name      AS doctor_name,
            d.specialisation,
            d.department
        FROM appointment a
        JOIN doctor d ON d.doctor_id = a.doctor_id
        WHERE a.patient_id = %s
        ORDER BY a.appointment_date DESC
        LIMIT 10
    """, (patient_id,))

    appointments = cur.fetchall()

    # Convert date and time to strings for JSON
    for appt in appointments:
        if appt["appointment_date"]:
            appt["appointment_date"] = str(appt["appointment_date"])
        if appt["appointment_time"]:
            appt["appointment_time"] = str(appt["appointment_time"])

    # Fetch billing records using patient_id directly.
    # The billing table has its own patient_id column so no JOIN is needed.
    cur.execute("""
        SELECT
            b.bill_id,
            b.bill_date,
            b.total_amount,
            b.amount_paid,
            b.discount,
            b.status
        FROM billing b
        WHERE b.patient_id = %s
        ORDER BY b.bill_date DESC
        LIMIT 10
    """, (patient_id,))

    bills = cur.fetchall()

    # Convert date to string for JSON
    for bill in bills:
        if bill["bill_date"]:
            bill["bill_date"] = str(bill["bill_date"])

    cur.close()
    conn.close()

    return {
        "patient_id":   patient_id,
        "appointments": appointments,
        "bills":        bills
    }