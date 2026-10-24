import os
import io
import csv
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from functools import wraps
from decimal import Decimal, ROUND_CEILING
from email.message import EmailMessage
import smtplib

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient, ReturnDocument
from bson import ObjectId
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "CHANGE_ME_TO_A_LONG_RANDOM_SECRET")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                 SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() == "true")

MONGO_URI = os.getenv("MONGO_URI", "")
DB_NAME = os.getenv("MONGO_DB_NAME", "smart_parking")
DEVICE_ID = os.getenv("DEVICE_ID", "parking-esp32-01")
DEVICE_TOKEN = os.getenv("DEVICE_TOKEN", "CHANGE_ME_DEVICE_TOKEN")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_EMAIL = os.getenv("SMTP_EMAIL", "")
SMTP_APP_PASSWORD = os.getenv("SMTP_APP_PASSWORD", "")
PARKING_RATE = Decimal(os.getenv("PARKING_RATE_PER_HOUR", "20"))
OVERSTAY_RATE = Decimal(os.getenv("OVERSTAY_RATE_PER_HOUR", "40"))
COMPENSATION = Decimal(os.getenv("OCCUPANCY_COMPENSATION", "40"))
INITIAL_WALLET = Decimal("500")
LOCAL_TZ = timezone(timedelta(hours=5, minutes=30))
SLOT_IDS = ["P1", "P2", "P3", "P4", "P5"]

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, tz_aware=True) if MONGO_URI else None
db = client[DB_NAME] if client else None
users = db["users"] if db is not None else None
slots = db["slots"] if db is not None else None
bookings = db["bookings"] if db is not None else None
commands = db["commands"] if db is not None else None
reports = db["reports"] if db is not None else None
waitlist = db["waitlist"] if db is not None else None
transactions = db["transactions"] if db is not None else None
password_resets = db["password_resets"] if db is not None else None
sensor_events = db["sensor_events"] if db is not None else None

def now_utc():
    return datetime.now(timezone.utc)

def iso(dt):
    return dt.isoformat() if dt else None

def money(value):
    return float(Decimal(str(value or 0)).quantize(Decimal("0.01")))

def ceil_hours(seconds):
    if seconds <= 0:
        return 0
    return int((Decimal(str(seconds)) / Decimal("3600")).to_integral_value(rounding=ROUND_CEILING))

def db_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if db is None:
            if request.path.startswith("/api/"):
                return jsonify(error="Database is not configured. Set MONGO_URI."), 503
            return render_template("error.html", page="error", error_message="Database is not configured. Add MONGO_URI to your environment."), 503
        return fn(*args, **kwargs)
    return wrapped

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify(error="Authentication required"), 401
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            if request.path.startswith("/api/"):
                return jsonify(error="Administrator access required"), 403
            flash("Administrator access required.", "error")
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)
    return wrapped

def current_user():
    if db is None or not session.get("user_id"):
        return None
    try:
        return users.find_one({"_id": ObjectId(session["user_id"])})
    except Exception:
        return None

def send_email(to, subject, body):
    if not SMTP_EMAIL or not SMTP_APP_PASSWORD or not to:
        app.logger.warning("Email not sent: SMTP_EMAIL / SMTP_APP_PASSWORD not configured. To=%s Subject=%s", to, subject)
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_EMAIL
    msg["To"] = to
    msg.set_content(body)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
            smtp.starttls()
            smtp.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception:
        app.logger.exception("SMTP delivery failed")
        return False

def record_transaction(user_id, kind, amount, note, booking_id=None, idempotency_key=None):
    amount = money(amount)
    if idempotency_key and transactions.find_one({"idempotency_key": idempotency_key}):
        return False
    transactions.insert_one({
        "user_id": str(user_id), "type": kind, "amount": amount, "note": note,
        "booking_id": str(booking_id) if booking_id else None,
        "idempotency_key": idempotency_key, "created_at": now_utc()
    })
    return True

def wallet_credit(user_id, amount, kind, note, booking_id=None, idempotency_key=None):
    if idempotency_key and transactions.find_one({"idempotency_key": idempotency_key}):
        return False
    users.update_one({"_id": ObjectId(str(user_id))}, {"$inc": {"wallet_balance": money(amount)}})
    record_transaction(user_id, kind, amount, note, booking_id, idempotency_key)
    return True

def wallet_debit(user_id, amount, kind, note, booking_id=None, allow_negative=False, idempotency_key=None):
    if idempotency_key and transactions.find_one({"idempotency_key": idempotency_key}):
        return True
    amount = money(amount)
    if not allow_negative:
        user = users.find_one({"_id": ObjectId(str(user_id))})
        if not user or float(user.get("wallet_balance", 0)) < amount:
            return False
    users.update_one({"_id": ObjectId(str(user_id))}, {"$inc": {"wallet_balance": -amount}})
    record_transaction(user_id, kind, -amount, note, booking_id, idempotency_key)
    return True

def ensure_slots():
    for sid in SLOT_IDS:
        slots.update_one({"_id": sid}, {"$setOnInsert": {
            "occupied": False, "sensor_known": False, "sensor_updated_at": None,
            "gate_state": "CLOSED", "status": "AVAILABLE", "updated_at": now_utc()
        }}, upsert=True)

def slot_sensor_is_fresh(slot):
    if not slot:
        return False
    updated = slot.get("sensor_updated_at")
    if not slot.get("sensor_known") or not updated:
        return False
    age = (now_utc() - updated).total_seconds()
    return 0 <= age <= 15

def slot_is_reliably_vacant(slot):
    return slot_sensor_is_fresh(slot) and not slot.get("occupied", True)

def overlaps(start, end, existing):
    return existing.get("start_at") and existing.get("end_at") and start < existing["end_at"] and end > existing["start_at"]

def active_booking_for_slot(slot_id, start, end):
    for b in bookings.find({"slot_id": slot_id, "status": {"$in": ["BOOKED", "ACTIVE"]}}):
        if overlaps(start, end, b):
            return b
    return None

def notify_waitlist_if_available(slot_id):
    slot = slots.find_one({"_id": slot_id})
    if not slot_is_reliably_vacant(slot):
        return
    now = now_utc()
    waiting = list(waitlist.find({"slot_id": slot_id, "notified": {"$ne": True}}).limit(50))
    for w in waiting:
        user = users.find_one({"_id": ObjectId(w["user_id"])})
        if user:
            sent = send_email(user.get("email"), f"Parking slot {slot_id} may be available",
                f"Hello {user.get('name','')},\n\nSlot {slot_id} has become vacant. Please revisit the booking page and complete the normal booking process. Availability is not reserved by this email and may change.\n\nSmart Parking")
            if sent:
                waitlist.update_one({"_id": w["_id"]}, {"$set": {"notified": True, "notified_at": now}})
    # Waitlist notifications never create a booking automatically.

def reconcile_overstay_charges():
    """Request-driven reconciliation suitable for serverless environments.
    Invoke on dashboard/session/exit requests and expose a protected scheduled endpoint
    for regular execution. Unique idempotency keys prevent duplicate interval charges.
    """
    if db is None:
        return
    now = now_utc()
    for b in bookings.find({"status": "ACTIVE", "actual_entry_at": {"$exists": True}}):
        end = b.get("end_at")
        if not end or now <= end:
            continue
        # first charge at 1 minute after booking expiry; next charges each 60 minutes later
        first_due = end + timedelta(minutes=1)
        if now < first_due:
            continue
        due_count = 1 + int((now - first_due).total_seconds() // 3600)
        already = int(b.get("overstay_charges_count", 0))
        if due_count <= already:
            continue
        user_id = b.get("user_id")
        for interval in range(already + 1, due_count + 1):
            key = f"overstay:{b['_id']}:{interval}"
            if transactions.find_one({"idempotency_key": key}):
                bookings.update_one({"_id": b["_id"]}, {"$max": {"overstay_charges_count": interval}})
                continue
            wallet_debit(user_id, OVERSTAY_RATE, "OVERSTAY_PENALTY",
                         f"Overstay charge #{interval} for slot {b.get('slot_id')}",
                         b["_id"], allow_negative=True, idempotency_key=key)
            bookings.update_one({"_id": b["_id"]}, {"$max": {"overstay_charges_count": interval}})
        total_penalties = transactions.count_documents({"user_id": str(user_id), "type": "OVERSTAY_PENALTY"})
        if total_penalties >= 3:
            users.update_one({"_id": ObjectId(str(user_id))},
                             {"$set": {"blacklisted": True, "blacklist_reason": "Three or more overstay penalties"}})

def get_page_context(page, **extra):
    user = current_user()
    context = {"page": page, "user": user, "role": session.get("role"), "slots": [], **extra}
    if db is not None and user and session.get("role") != "admin":
        reconcile_overstay_charges()
        context["wallet_balance"] = money(user.get("wallet_balance", 0))
    return context

@app.before_request
def lazy_setup():
    if db is not None:
        try:
            ensure_slots()
        except Exception:
            app.logger.exception("Database initialization error")

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("admin_dashboard" if session.get("role") == "admin" else "dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
@db_required
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        # Admin credentials are environment-only; no admin signup/reset route exists.
        if email == ADMIN_EMAIL and ADMIN_PASSWORD and secrets.compare_digest(ADMIN_PASSWORD, password):
            session.clear()
            session["user_id"] = "admin"
            session["role"] = "admin"
            session["email"] = ADMIN_EMAIL
            return redirect(url_for("admin_dashboard"))
        user = users.find_one({"email": email})
        if user and check_password_hash(user.get("password_hash", ""), password) and not user.get("disabled", False):
            session.clear()
            session["user_id"] = str(user["_id"])
            session["role"] = "user"
            session["email"] = user["email"]
            return redirect(url_for("dashboard"))
        flash("Invalid email/password or account disabled.", "error")
    return render_template("login.html", page="login", user=None)

@app.route("/signup", methods=["GET", "POST"])
@db_required
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        mobile = request.form.get("mobile", "").strip()
        rfid = request.form.get("rfid", "").strip().upper()
        password = request.form.get("password", "")
        if not name or not email or not mobile or not password:
            flash("Please complete all required fields.", "error")
            return render_template("signup.html", page="signup", user=None)
        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return render_template("signup.html", page="signup", user=None)
        if email == ADMIN_EMAIL or users.find_one({"$or": [{"email": email}, {"mobile": mobile}]}):
            flash("Email or mobile number is already registered.", "error")
            return render_template("signup.html", page="signup", user=None)
        if rfid and users.find_one({"rfid": rfid}):
            flash("This RFID identifier is already linked to an account.", "error")
            return render_template("signup.html", page="signup", user=None)
        doc = {"name": name, "email": email, "mobile": mobile, "rfid": rfid or None,
               "password_hash": generate_password_hash(password), "wallet_balance": float(INITIAL_WALLET),
               "blacklisted": False, "disabled": False, "role": "user",
               "created_at": now_utc()}
        result = users.insert_one(doc)
        record_transaction(result.inserted_id, "WELCOME_CREDIT", INITIAL_WALLET,
                           "Initial wallet balance", idempotency_key=f"welcome:{result.inserted_id}")
        session.clear()
        session["user_id"] = str(result.inserted_id)
        session["role"] = "user"
        session["email"] = email
        flash("Account created. ₹500 welcome balance added.", "success")
        return redirect(url_for("dashboard"))
    return render_template("signup.html", page="signup", user=None)

@app.route("/forgot-password", methods=["GET", "POST"])
@db_required
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = users.find_one({"email": email})
        # Generic response avoids revealing whether an account exists.
        if user:
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            password_resets.insert_one({"user_id": str(user["_id"]), "token_hash": token_hash,
                                        "expires_at": now_utc() + timedelta(minutes=30),
                                        "used": False, "created_at": now_utc()})
            link = url_for("reset_password", token=token, _external=True)
            send_email(email, "Reset your Smart Parking password",
                       f"Use this link within 30 minutes to reset your password:\n\n{link}\n\nIf you did not request this, ignore this email.")
        flash("If the email is registered, a password-reset link has been sent.", "success")
    return render_template("forgot_password.html", page="forgot", user=None)

@app.route("/reset-password/<token>", methods=["GET", "POST"])
@db_required
def reset_password(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    reset = password_resets.find_one({"token_hash": token_hash, "used": False, "expires_at": {"$gt": now_utc()}})
    if not reset:
        flash("This reset link is invalid or expired.", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        password = request.form.get("password", "")
        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
        else:
            users.update_one({"_id": ObjectId(reset["user_id"])},
                             {"$set": {"password_hash": generate_password_hash(password)}})
            password_resets.update_one({"_id": reset["_id"]}, {"$set": {"used": True, "used_at": now_utc()}})
            flash("Password updated. Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("reset_password.html", page="reset", user=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
@db_required
def dashboard():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    reconcile_overstay_charges()
    user = current_user()
    if not user:
        session.clear()
        return redirect(url_for("login"))
    current = list(bookings.find({"user_id": str(user["_id"]), "status": {"$in": ["BOOKED", "ACTIVE"]}}).sort("start_at", 1))
    slot_docs = list(slots.find())
    return render_template("dashboard.html", page="dashboard", user=user, current_bookings=current,
                           slots=slot_docs, wallet_balance=money(user.get("wallet_balance", 0)))

@app.route("/book", methods=["GET", "POST"])
@login_required
@db_required
def book():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    reconcile_overstay_charges()
    user = current_user()
    if user.get("blacklisted"):
        flash("Your account is blacklisted due to repeated overstay penalties. Contact the administrator.", "error")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        try:
            start = datetime.fromisoformat(request.form["start_at"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(request.form["end_at"].replace("Z", "+00:00"))
            if start.tzinfo is None:
                start = start.replace(tzinfo=LOCAL_TZ)
            if end.tzinfo is None:
                end = end.replace(tzinfo=LOCAL_TZ)
            start = start.astimezone(timezone.utc)
            end = end.astimezone(timezone.utc)
        except Exception:
            flash("Select valid start and end date/time.", "error")
            return redirect(url_for("book"))
        now = now_utc()
        if start < now or end <= start or (end - start).total_seconds() > 24 * 3600:
            flash("Invalid booking period. Bookings must be in the future and no longer than 24 hours.", "error")
            return redirect(url_for("book"))
        duration_hours = ceil_hours((end - start).total_seconds())
        amount = money(PARKING_RATE * duration_hours)
        if float(user.get("wallet_balance", 0)) < amount:
            flash(f"Insufficient wallet balance. Booking cost is ₹{amount:.2f}.", "error")
            return redirect(url_for("book"))
        requested_slot = request.form.get("slot_id", "")
        candidates = [requested_slot] if requested_slot in SLOT_IDS else SLOT_IDS
        selected = None
        for sid in candidates:
            slot = slots.find_one({"_id": sid})
            if not slot_is_reliably_vacant(slot):
                continue
            if active_booking_for_slot(sid, start, end):
                continue
            selected = sid
            break
        if not selected:
            # Offer a waitlist entry; does not create a reservation.
            waitlist.update_one({"user_id": str(user["_id"]), "start_at": start, "end_at": end},
                {"$setOnInsert": {"user_id": str(user["_id"]), "email": user["email"],
                 "start_at": start, "end_at": end, "slot_id": requested_slot if requested_slot in SLOT_IDS else None,
                 "notified": False, "created_at": now_utc()}}, upsert=True)
            flash("No slot is currently available for that time. You are on the notification queue if a slot was selected.", "error")
            return redirect(url_for("book"))
        # Debit and insert booking. This prototype uses a simple sequential operation;
        # production should wrap wallet debit + booking creation in a MongoDB transaction.
        if not wallet_debit(user["_id"], amount, "BOOKING_DEBIT", f"Booking {selected}", idempotency_key=f"booking-debit:{secrets.token_hex(12)}"):
            flash("Unable to debit wallet. Please try again.", "error")
            return redirect(url_for("book"))
        booking_doc = {"user_id": str(user["_id"]), "slot_id": selected, "start_at": start, "end_at": end,
                       "status": "BOOKED", "booking_amount": amount, "base_charged": amount,
                       "penalty_charged": 0.0, "overstay_charges_count": 0,
                       "created_at": now_utc(), "entry_method": None, "actual_entry_at": None, "actual_exit_at": None}
        result = bookings.insert_one(booking_doc)
        flash(f"Slot {selected} booked. ₹{amount:.2f} deducted from your wallet.", "success")
        return redirect(url_for("dashboard"))
    ensure_slots()
    return render_template("book.html", page="book", user=user,
                           slots=list(slots.find().sort("_id", 1)), wallet_balance=money(user.get("wallet_balance", 0)))

@app.route("/booking/<booking_id>/entry", methods=["POST"])
@login_required
@db_required
def web_entry(booking_id):
    reconcile_overstay_charges()
    user = current_user()
    try:
        b = bookings.find_one({"_id": ObjectId(booking_id), "user_id": str(user["_id"]), "status": "BOOKED"})
    except Exception:
        b = None
    if not b:
        flash("No eligible booking found.", "error")
        return redirect(url_for("dashboard"))
    slot = slots.find_one({"_id": b["slot_id"]})
    if not slot_sensor_is_fresh(slot):
        flash("The slot sensor is offline or its data is stale. Your booking is unchanged; please retry shortly.", "error")
        return redirect(url_for("dashboard"))
    if slot.get("occupied", True):
        refund_amount = money(b.get("booking_amount", 0))
        bookings.update_one({"_id": b["_id"], "status": "BOOKED"},
                            {"$set": {"status": "CANCELLED", "cancel_reason": "Booked slot occupied",
                                      "cancelled_at": now_utc()}})
        wallet_credit(user["_id"], refund_amount, "BOOKING_REFUND", "Refund: booked slot occupied", b["_id"],
                      idempotency_key=f"occupied-refund:{b['_id']}")
        wallet_credit(user["_id"], COMPENSATION, "COMPENSATION", "Compensation: booked slot occupied", b["_id"],
                      idempotency_key=f"occupied-compensation:{b['_id']}")
        flash(f"Slot {b['slot_id']} is occupied. Booking cancelled; ₹{refund_amount + float(COMPENSATION):.2f} credited.", "error")
        return redirect(url_for("dashboard"))
    cmd = {"device_id": DEVICE_ID, "command_id": secrets.token_urlsafe(18), "slot_id": b["slot_id"],
           "action": "OPEN_GATE", "operation": "ENTRY", "user_id": str(user["_id"]),
           "booking_id": str(b["_id"]), "status": "PENDING", "created_at": now_utc(),
           "expires_at": int((now_utc() + timedelta(seconds=30)).timestamp())}
    commands.insert_one(cmd)
    bookings.update_one({"_id": b["_id"], "status": "BOOKED"},
                        {"$set": {"entry_method": "WEB", "entry_requested_at": now_utc(),
                                  "entry_command_id": cmd["command_id"]}})
    flash("Entry request sent to the parking controller. Wait for gate confirmation.", "success")
    return redirect(url_for("dashboard"))

@app.route("/booking/<booking_id>/extend", methods=["POST"])
@login_required
@db_required
def extend_booking(booking_id):
    user = current_user()
    try:
        b = bookings.find_one({"_id": ObjectId(booking_id), "user_id": str(user["_id"]), "status": {"$in": ["BOOKED", "ACTIVE"]}})
    except Exception:
        b = None
    if not b:
        flash("Booking not found.", "error")
        return redirect(url_for("dashboard"))
    try:
        new_end = datetime.fromisoformat(request.form["new_end_at"].replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        flash("Choose a valid new end time.", "error")
        return redirect(url_for("dashboard"))
    if new_end <= b["end_at"]:
        flash("New end time must be later than current end time.", "error")
        return redirect(url_for("dashboard"))
    if active_booking_for_slot(b["slot_id"], b["end_at"], new_end) not in (None, b):
        flash("This slot is not available for the requested extension.", "error")
        return redirect(url_for("dashboard"))
    extra_hours = ceil_hours((new_end - b["end_at"]).total_seconds())
    extra_cost = money(PARKING_RATE * extra_hours)
    user = users.find_one({"_id": ObjectId(str(user["_id"]))})
    if float(user.get("wallet_balance", 0)) < extra_cost:
        flash(f"Insufficient wallet balance for extension (₹{extra_cost:.2f}).", "error")
        return redirect(url_for("dashboard"))
    if wallet_debit(user["_id"], extra_cost, "EXTENSION_DEBIT", "Booking extension", b["_id"],
                    idempotency_key=f"extend:{b['_id']}:{new_end.isoformat()}"):
        bookings.update_one({"_id": b["_id"]}, {"$set": {"end_at": new_end},
                            "$inc": {"booking_amount": extra_cost, "base_charged": extra_cost}})
        flash(f"Booking extended. ₹{extra_cost:.2f} deducted.", "success")
    return redirect(url_for("dashboard"))

@app.route("/reports/new", methods=["POST"])
@login_required
@db_required
def create_report():
    user = current_user()
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "Other")
    description = request.form.get("description", "").strip()
    if not title or not description:
        flash("Enter a title and description.", "error")
        return redirect(url_for("report_issue"))
    reports.insert_one({"user_id": str(user["_id"]), "name": user.get("name"), "email": user.get("email"),
                        "slot_id": request.form.get("slot_id") or None, "title": title, "category": category,
                        "description": description, "status": "OPEN", "created_at": now_utc()})
    send_email(ADMIN_EMAIL, f"Smart Parking report: {title}",
               f"From: {user.get('name')} ({user.get('email')})\nCategory: {category}\nSlot: {request.form.get('slot_id')}\n\n{description}")
    flash("Report submitted to the administrator.", "success")
    return redirect(url_for("report_issue"))

@app.route("/settings", methods=["GET", "POST"])
@login_required
@db_required
def settings():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    user = current_user()
    if request.method == "POST":
        mobile = request.form.get("mobile", "").strip()
        rfid = request.form.get("rfid", "").strip().upper()
        duplicate = users.find_one({"rfid": rfid, "_id": {"$ne": user["_id"]}}) if rfid else None
        if duplicate:
            flash("That RFID is already linked to another user.", "error")
        elif not mobile:
            flash("Mobile number is required.", "error")
        else:
            users.update_one({"_id": user["_id"]}, {"$set": {"mobile": mobile, "rfid": rfid or None}})
            flash("Settings updated.", "success")
        return redirect(url_for("settings"))
    return render_template("settings.html", page="settings", user=user,
                           wallet_balance=money(user.get("wallet_balance", 0)),
                           transactions=list(transactions.find({"user_id": str(user["_id"])}).sort("created_at", -1).limit(30)))

@app.route("/wallet/recharge", methods=["POST"])
@login_required
@db_required
def wallet_recharge():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    try:
        amount = Decimal(request.form.get("amount", "0"))
    except Exception:
        amount = Decimal("0")
    if amount <= 0 or amount > 50000:
        flash("Enter a recharge amount between ₹1 and ₹50,000.", "error")
        return redirect(url_for("settings"))
    user = current_user()
    # DEMO ONLY: this credits funds without processing an actual payment.
    wallet_credit(user["_id"], amount, "DEMO_RECHARGE", "Manual demo wallet recharge",
                  idempotency_key=f"demo-recharge:{secrets.token_hex(16)}")
    flash(f"₹{money(amount):.2f} added in DEMO mode. No real payment was processed.", "success")
    return redirect(url_for("settings"))

@app.route("/waitlist", methods=["POST"])
@login_required
@db_required
def join_waitlist():
    user = current_user()
    slot_id = request.form.get("slot_id", "")
    if slot_id not in SLOT_IDS:
        flash("Select a slot for availability notifications.", "error")
        return redirect(url_for("book"))
    try:
        start = datetime.fromisoformat(request.form["start_at"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(request.form["end_at"].replace("Z", "+00:00"))
        if start.tzinfo is None:
            start = start.replace(tzinfo=LOCAL_TZ)
        if end.tzinfo is None:
            end = end.replace(tzinfo=LOCAL_TZ)
        start = start.astimezone(timezone.utc)
        end = end.astimezone(timezone.utc)
    except Exception:
        flash("Choose a valid time period.", "error")
        return redirect(url_for("book"))
    waitlist.update_one({"user_id": str(user["_id"]), "slot_id": slot_id, "start_at": start, "end_at": end},
        {"$setOnInsert": {"user_id": str(user["_id"]), "email": user["email"], "slot_id": slot_id,
         "start_at": start, "end_at": end, "notified": False, "created_at": now_utc()}}, upsert=True)
    flash("You will receive an email if this slot becomes available. You must return and book normally.", "success")
    return redirect(url_for("book"))

@app.route("/admin")
@login_required
@admin_required
@db_required
def admin_dashboard():
    reconcile_overstay_charges()
    ensure_slots()
    stats = {
        "users": users.count_documents({}),
        "active_bookings": bookings.count_documents({"status": {"$in": ["BOOKED", "ACTIVE"]}}),
        "open_reports": reports.count_documents({"status": "OPEN"}),
        "revenue": round(sum(float(t.get("amount", 0)) for t in transactions.find({"amount": {"$lt": 0}})), 2) * -1
    }
    return render_template("admin_overview.html", page="admin_overview", user=None, stats=stats)

@app.route("/admin/slots")
@login_required
@admin_required
@db_required
def admin_slots_page():
    ensure_slots()
    return render_template("admin_slots.html", page="admin_slots", user=None, admin_slots=list(slots.find().sort("_id", 1)))

@app.route("/admin/users")
@login_required
@admin_required
@db_required
def admin_users_page():
    return render_template("admin_users.html", page="admin_users", user=None,
                           admin_users=list(users.find().sort("created_at", -1).limit(500)))

@app.route("/admin/bookings")
@login_required
@admin_required
@db_required
def admin_bookings_page():
    return render_template("admin_bookings.html", page="admin_bookings", user=None,
                           admin_bookings=list(bookings.find().sort("created_at", -1).limit(500)))

@app.route("/admin/reports")
@login_required
@admin_required
@db_required
def admin_reports_page():
    return render_template("admin_reports.html", page="admin_reports", user=None,
                           admin_reports=list(reports.find().sort("created_at", -1).limit(500)))

@app.route("/admin/transactions")
@login_required
@admin_required
@db_required
def admin_transactions_page():
    return render_template("admin_transactions.html", page="admin_transactions", user=None,
                           admin_transactions=list(transactions.find().sort("created_at", -1).limit(500)))

@app.route("/past-bookings")
@login_required
@db_required
def past_bookings_page():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    user = current_user()
    past = list(bookings.find({"user_id": str(user["_id"]), "status": {"$in": ["COMPLETED", "CANCELLED", "NO_SHOW"]}}).sort("created_at", -1).limit(200))
    return render_template("past_bookings.html", page="past_bookings", user=user, past_bookings=past)

@app.route("/reports", methods=["GET"])
@login_required
@db_required
def report_issue():
    if session.get("role") == "admin":
        return redirect(url_for("admin_reports_page"))
    return render_template("report_issue.html", page="report_issue", user=current_user(), slots=list(slots.find().sort("_id", 1)))

@app.route("/admin/users/<user_id>/blacklist", methods=["POST"])
@login_required
@admin_required
@db_required
def admin_blacklist(user_id):
    users.update_one({"_id": ObjectId(user_id)}, {"$set": {"blacklisted": True, "blacklist_reason": "Administrator action"}})
    flash("User blacklisted.", "success")
    return redirect(url_for("admin_users_page"))

@app.route("/admin/users/<user_id>/whitelist", methods=["POST"])
@login_required
@admin_required
@db_required
def admin_whitelist(user_id):
    users.update_one({"_id": ObjectId(user_id)}, {"$set": {"blacklisted": False, "blacklist_reason": None}})
    flash("User whitelisted.", "success")
    return redirect(url_for("admin_users_page"))

@app.route("/admin/reports/<report_id>/solve", methods=["POST"])
@login_required
@admin_required
@db_required
def solve_report(report_id):
    reports.update_one({"_id": ObjectId(report_id)}, {"$set": {"status": "SOLVED", "solved_at": now_utc(), "solved_by": ADMIN_EMAIL}})
    flash("Report marked as solved.", "success")
    return redirect(url_for("admin_reports_page"))

@app.route("/admin/slots/<slot_id>/gate", methods=["POST"])
@login_required
@admin_required
@db_required
def admin_gate(slot_id):
    if slot_id not in SLOT_IDS:
        flash("Invalid slot.", "error")
        return redirect(url_for("admin_slots_page"))
    action = request.form.get("action")
    if action not in ("OPEN_GATE", "CLOSE_GATE"):
        flash("Invalid gate action.", "error")
        return redirect(url_for("admin_slots_page"))
    commands.insert_one({"device_id": DEVICE_ID, "command_id": secrets.token_urlsafe(18),
        "slot_id": slot_id, "action": action, "operation": "ADMIN", "status": "PENDING",
        "created_at": now_utc(), "expires_at": int((now_utc() + timedelta(seconds=30)).timestamp()),
        "requested_by": ADMIN_EMAIL})
    flash(f"{action.replace('_', ' ').title()} command queued for {slot_id}.", "success")
    return redirect(url_for("admin_slots_page"))

@app.route("/admin/export/<kind>.<fmt>")
@login_required
@admin_required
@db_required
def export_admin(kind, fmt):
    collections = {"users": users, "bookings": bookings, "reports": reports, "transactions": transactions}
    if kind not in collections or fmt not in ("csv", "pdf"):
        return "Unsupported export", 400
    rows = list(collections[kind].find().limit(10000))
    normalized = []
    for row in rows:
        normalized.append({k: (str(v) if isinstance(v, (ObjectId, datetime)) else v)
                           for k, v in row.items() if k != "password_hash"})
    if fmt == "csv":
        output = io.StringIO()
        keys = sorted({k for row in normalized for k in row.keys()})
        writer = csv.DictWriter(output, fieldnames=keys or ["empty"], extrasaction="ignore")
        writer.writeheader()
        for row in normalized:
            writer.writerow(row)
        resp = make_response(output.getvalue())
        resp.headers["Content-Type"] = "text/csv; charset=utf-8"
        resp.headers["Content-Disposition"] = f"attachment; filename={kind}_report.csv"
        return resp
    try:
        from reportlab.lib.pagesizes import landscape, A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=landscape(A4), rightMargin=20, leftMargin=20, topMargin=20, bottomMargin=20)
        styles = getSampleStyleSheet()
        story = [Paragraph(f"Smart Parking - {kind.title()} Report", styles["Title"]), Spacer(1, 12)]
        keys = sorted({k for row in normalized for k in row.keys()})
        data = [[k for k in keys]]
        for row in normalized[:500]:
            data.append([str(row.get(k, ""))[:120] for k in keys])
        table = Table(data, repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#2563eb")),
                                   ("TEXTCOLOR", (0,0), (-1,0), colors.white),
                                   ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
                                   ("FONTSIZE", (0,0), (-1,-1), 6),
                                   ("VALIGN", (0,0), (-1,-1), "TOP")]))
        story.append(table)
        doc.build(story)
        resp = make_response(buf.getvalue())
        resp.headers["Content-Type"] = "application/pdf"
        resp.headers["Content-Disposition"] = f"attachment; filename={kind}_report.pdf"
        return resp
    except Exception as exc:
        app.logger.exception("PDF export failed")
        return f"PDF export failed: {exc}", 500

# ---------------- Device API ----------------

def device_auth_ok():
    return request.headers.get("X-Device-ID") == DEVICE_ID and \
           secrets.compare_digest(request.headers.get("X-Device-Token", ""), DEVICE_TOKEN)

@app.route("/api/device/sensors", methods=["POST"])
@db_required
def device_sensors():
    if not device_auth_ok():
        return jsonify(error="Unauthorized device"), 401
    data = request.get_json(silent=True) or {}
    if data.get("device_id") != DEVICE_ID:
        return jsonify(error="Device ID mismatch"), 400
    received = data.get("slots", {})
    updated = now_utc()
    for sid in SLOT_IDS:
        value = received.get(sid)
        if isinstance(value, dict):
            value = value.get("occupied")
        if not isinstance(value, bool):
            continue
        slots.update_one({"_id": sid}, {"$set": {
            "occupied": value, "sensor_known": True, "sensor_updated_at": updated,
            "status": "OCCUPIED" if value else "AVAILABLE", "updated_at": updated
        }}, upsert=True)
        if value:
            active = bookings.find_one({"slot_id": sid, "status": "ACTIVE"})
            if active and not active.get("vehicle_detected_at"):
                bookings.update_one({"_id": active["_id"], "vehicle_detected_at": {"$exists": False}},
                                    {"$set": {"vehicle_detected_at": updated}})
        if not value:
            notify_waitlist_if_available(sid)
    close_sessions_for_vacant_slots()
    return jsonify(ok=True, received_at=iso(updated))

@app.route("/api/device/rfid-scan", methods=["POST"])
@db_required
def device_rfid_scan():
    if not device_auth_ok():
        return jsonify(error="Unauthorized device"), 401
    data = request.get_json(silent=True) or {}
    uid = str(data.get("uid", "")).strip().upper()
    user = users.find_one({"rfid": uid, "disabled": {"$ne": True}}) if uid else None
    if not user:
        return jsonify(authorized=False, message="Unknown or disabled RFID credential"), 200
    if user.get("blacklisted"):
        return jsonify(authorized=False, message="User is blacklisted"), 200
    b = bookings.find_one({"user_id": str(user["_id"]), "status": "BOOKED"}, sort=[("start_at", 1)])
    if not b:
        return jsonify(authorized=False, message="Authorized RFID but no eligible booking"), 200
    slot = slots.find_one({"_id": b["slot_id"]})
    # Prefer fresh hardware sensor readings included with scan.
    incoming = data.get("slots", {})
    incoming_value = incoming.get(b["slot_id"])
    if isinstance(incoming_value, dict):
        incoming_value = incoming_value.get("occupied")
    occupied = incoming_value if isinstance(incoming_value, bool) else None
    if occupied is True:
        amount = money(b.get("booking_amount", 0))
        bookings.update_one({"_id": b["_id"], "status": "BOOKED"},
            {"$set": {"status": "CANCELLED", "cancel_reason": "Booked slot occupied", "cancelled_at": now_utc()}})
        wallet_credit(user["_id"], amount, "BOOKING_REFUND", "Refund: booked slot occupied", b["_id"], f"occupied-refund:{b['_id']}")
        wallet_credit(user["_id"], COMPENSATION, "COMPENSATION", "Compensation: booked slot occupied", b["_id"], f"occupied-compensation:{b['_id']}")
        return jsonify(authorized=False, message="Booked slot occupied; booking cancelled and refund plus compensation credited"), 200
    if occupied is not False or not slot_sensor_is_fresh(slot) or slot.get("occupied", True):
        return jsonify(authorized=False, message="Slot sensor status is stale or inconsistent; booking unchanged, retry entry shortly"), 200
    cmd = {"device_id": DEVICE_ID, "command_id": secrets.token_urlsafe(18), "slot_id": b["slot_id"],
           "action": "OPEN_GATE", "operation": "ENTRY", "user_id": str(user["_id"]),
           "booking_id": str(b["_id"]), "status": "PENDING", "created_at": now_utc(),
           "expires_at": int((now_utc() + timedelta(seconds=30)).timestamp())}
    commands.insert_one(cmd)
    bookings.update_one({"_id": b["_id"], "status": "BOOKED"},
                        {"$set": {"entry_method": "RFID", "entry_requested_at": now_utc(),
                                  "entry_command_id": cmd["command_id"]}})
    return jsonify(authorized=True, action="OPEN_GATE", operation="ENTRY",
                   slot_id=b["slot_id"], command_id=cmd["command_id"], message="Entry authorized"), 200

@app.route("/api/device/commands", methods=["GET"])
@db_required
def device_commands():
    if not device_auth_ok():
        return jsonify(error="Unauthorized device"), 401
    if request.args.get("device_id") != DEVICE_ID:
        return jsonify(error="Device ID mismatch"), 400
    now_ts = int(now_utc().timestamp())
    pending = list(commands.find({"device_id": DEVICE_ID, "status": "PENDING",
                                  "expires_at": {"$gt": now_ts}}).sort("created_at", 1).limit(10))
    result = []
    for c in pending:
        result.append({"command_id": c["command_id"], "action": c["action"], "operation": c.get("operation", ""),
                       "slot_id": c["slot_id"], "expires_at": c["expires_at"]})
        commands.update_one({"_id": c["_id"], "status": "PENDING"},
                            {"$set": {"status": "DISPATCHED", "dispatched_at": now_utc()}})
    return jsonify(commands=result)

@app.route("/api/device/commands/ack", methods=["POST"])
@db_required
def device_command_ack():
    if not device_auth_ok():
        return jsonify(error="Unauthorized device"), 401
    data = request.get_json(silent=True) or {}
    command_id = data.get("command_id")
    status = data.get("status")
    allowed = {"EXECUTED", "REJECTED_SLOT_OCCUPIED", "REJECTED_INVALID_COMMAND",
               "FAILED_GATE_BUSY", "EXPIRED", "FAILED_WIFI"}
    if not command_id or status not in allowed:
        return jsonify(error="Invalid acknowledgement"), 400
    cmd = commands.find_one_and_update({"device_id": DEVICE_ID, "command_id": command_id,
                                        "status": {"$in": ["PENDING", "DISPATCHED"]}},
                                       {"$set": {"status": status, "ack_at": now_utc(),
                                                 "ack_payload": data}},
                                       return_document=ReturnDocument.AFTER)
    if not cmd:
        return jsonify(ok=True, duplicate_or_unknown=True), 200
    if cmd.get("booking_id") and cmd.get("operation") == "ENTRY" and status == "EXECUTED":
        bookings.update_one({"_id": ObjectId(cmd["booking_id"]), "status": "BOOKED"},
            {"$set": {"status": "ACTIVE", "actual_entry_at": now_utc()}})
    if cmd.get("booking_id") and cmd.get("operation") == "EXIT" and status == "EXECUTED":
        bookings.update_one({"_id": ObjectId(cmd["booking_id"]), "status": "ACTIVE"},
            {"$set": {"exit_command_executed_at": now_utc()}})
    if status == "REJECTED_SLOT_OCCUPIED" and cmd.get("booking_id"):
        b = bookings.find_one({"_id": ObjectId(cmd["booking_id"]), "status": "BOOKED"})
        if b:
            bookings.update_one({"_id": b["_id"]}, {"$set": {"status": "CANCELLED", "cancel_reason": "Slot occupied", "cancelled_at": now_utc()}})
            wallet_credit(b["user_id"], b.get("booking_amount", 0), "BOOKING_REFUND", "Refund: slot occupied", b["_id"], f"occupied-refund:{b['_id']}")
            wallet_credit(b["user_id"], COMPENSATION, "COMPENSATION", "Compensation: slot occupied", b["_id"], f"occupied-compensation:{b['_id']}")
    return jsonify(ok=True)

@app.route("/api/device/heartbeat", methods=["POST"])
@db_required
def device_heartbeat():
    if not device_auth_ok():
        return jsonify(error="Unauthorized device"), 401
    return jsonify(ok=True, server_time=int(now_utc().timestamp()))

@app.route("/api/booking-status")
@login_required
@db_required
def booking_status():
    reconcile_overstay_charges()
    user = current_user()
    rows = list(bookings.find({"user_id": str(user["_id"]), "status": {"$in": ["BOOKED", "ACTIVE"]}}).sort("start_at", 1))
    return jsonify(bookings=[{"id": str(b["_id"]), "slot_id": b["slot_id"], "status": b["status"],
                              "start_at": iso(b.get("start_at")), "end_at": iso(b.get("end_at")),
                              "actual_entry_at": iso(b.get("actual_entry_at")),
                              "booking_amount": b.get("booking_amount", 0),
                              "overstay_charges_count": b.get("overstay_charges_count", 0)} for b in rows])

@app.route("/booking/<booking_id>/exit", methods=["POST"])
@login_required
@db_required
def web_exit(booking_id):
    reconcile_overstay_charges()
    user = current_user()
    try:
        b = bookings.find_one({"_id": ObjectId(booking_id), "user_id": str(user["_id"]), "status": "ACTIVE"})
    except Exception:
        b = None
    if not b:
        flash("No active parking session found. Entry must be confirmed first.", "error")
        return redirect(url_for("dashboard"))
    cmd = {"device_id": DEVICE_ID, "command_id": secrets.token_urlsafe(18), "slot_id": b["slot_id"],
           "action": "OPEN_GATE", "operation": "EXIT", "user_id": str(user["_id"]),
           "booking_id": str(b["_id"]), "status": "PENDING", "created_at": now_utc(),
           "expires_at": int((now_utc() + timedelta(seconds=30)).timestamp())}
    commands.insert_one(cmd)
    bookings.update_one({"_id": b["_id"]}, {"$set": {"exit_requested_at": now_utc(), "exit_command_id": cmd["command_id"]}})
    flash("Exit command queued. The session will close after the sensor confirms vacancy.", "success")
    return redirect(url_for("dashboard"))

# ESP32 sensor uploads provide the physical vacancy signal. Close an active
# session after vacancy following an acknowledged EXIT command.
def close_sessions_for_vacant_slots():
    if db is None:
        return
    for sid in SLOT_IDS:
        slot = slots.find_one({"_id": sid})
        if not slot_is_reliably_vacant(slot):
            continue
        b = bookings.find_one({"slot_id": sid, "status": "ACTIVE",
                                "exit_command_executed_at": {"$exists": True},
                                "vehicle_detected_at": {"$exists": True}})
        if b and slot.get("sensor_updated_at") and slot["sensor_updated_at"] > b["exit_command_executed_at"]:
            now = now_utc()
            bookings.update_one({"_id": b["_id"], "status": "ACTIVE"},
                {"$set": {"status": "COMPLETED", "actual_exit_at": now, "completed_at": now}})
            slots.update_one({"_id": sid}, {"$set": {"status": "AVAILABLE", "occupied": False}})
            notify_waitlist_if_available(sid)


@app.context_processor
def inject_global_context():
    return {"role": session.get("role"), "logged_in_email": session.get("email")}

@app.route("/api/availability")
@login_required
@db_required
def api_availability():
    try:
        start = datetime.fromisoformat(request.args.get("start_at", "").replace("Z", "+00:00"))
        end = datetime.fromisoformat(request.args.get("end_at", "").replace("Z", "+00:00"))
        if start.tzinfo is None or end.tzinfo is None or end <= start or start < now_utc():
            return jsonify(error="Invalid booking interval", available_slots=[]), 400
        start, end = start.astimezone(timezone.utc), end.astimezone(timezone.utc)
    except Exception:
        return jsonify(error="Provide valid start_at and end_at", available_slots=[]), 400
    ensure_slots()
    available = []
    states = []
    for sid in SLOT_IDS:
        slot = slots.find_one({"_id": sid})
        sensor_ok = slot_is_reliably_vacant(slot)
        booking_conflict = active_booking_for_slot(sid, start, end) is not None
        is_available = sensor_ok and not booking_conflict
        states.append({"slot_id": sid, "available": is_available,
                       "reason": "Available" if is_available else
                                 ("Sensor data unavailable or slot occupied" if not sensor_ok else "Already reserved for this period")})
        if is_available:
            available.append(sid)
    return jsonify(available_slots=available, slots=states)

@app.route("/api/cron/maintenance", methods=["GET", "POST"])
@db_required
def cron_maintenance():
    expected = os.getenv("CRON_SECRET", "")
    supplied = request.headers.get("Authorization", "").replace("Bearer ", "", 1)
    if not expected or not secrets.compare_digest(expected, supplied):
        return jsonify(error="Unauthorized"), 401
    reconcile_overstay_charges()
    now = now_utc()
    reminder_window_start = now + timedelta(minutes=9)
    reminder_window_end = now + timedelta(minutes=11)
    reminders_sent = 0
    for b in bookings.find({"status": {"$in": ["BOOKED", "ACTIVE"]},
                            "end_at": {"$gte": reminder_window_start, "$lte": reminder_window_end},
                            "reminder_sent_at": {"$exists": False}}):
        user = users.find_one({"_id": ObjectId(b["user_id"])})
        if user:
            ok = send_email(user.get("email"), f"Parking reminder: {b['slot_id']} ends in 10 minutes",
                f"Hello {user.get('name','')},\\n\\nYour parking booking for slot {b['slot_id']} is scheduled to end at {b['end_at'].astimezone(LOCAL_TZ).strftime('%d %b %Y, %I:%M %p')} IST. Please exit on time or extend your booking if available. Overstay charges are ₹40 per hour, starting one minute after expiry.\\n\\nParkEase")
            if ok:
                bookings.update_one({"_id": b["_id"], "reminder_sent_at": {"$exists": False}},
                                    {"$set": {"reminder_sent_at": now}})
                reminders_sent += 1
    return jsonify(ok=True, reminders_sent=reminders_sent, checked_at=iso(now))

if __name__ == "__main__":
    if not ADMIN_PASSWORD:
        print("WARNING: Set ADMIN_PASSWORD in .env before using the admin login.")
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
