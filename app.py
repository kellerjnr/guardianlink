from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
import os
import secrets

from flask import Flask, flash, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
database_url = os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'securealert.db'}")
# Some hosting providers still supply the older postgres:// prefix.
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "local-demo-secret-change-before-production")
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
db = SQLAlchemy(app)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf", "mp3", "wav"}
INCIDENT_TYPES = ["Kidnapping/abduction", "Armed robbery", "Suspicious activity", "Violence", "Missing person", "Unsafe road", "Other"]
STATUSES = ["Submitted", "Under review", "Verified", "In progress", "Resolved", "Rejected"]


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="citizen")
    trusted_contact = db.Column(db.String(50))
    reports = db.relationship("Incident", backref="reporter", lazy=True)


class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_type = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    location_name = db.Column(db.String(180))
    is_anonymous = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(30), default="Submitted")
    evidence_file = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    reporter_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)


class SafetySession(db.Model):
    """Short, user-started location-sharing session for the academic demo."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    last_latitude = db.Column(db.Float)
    last_longitude = db.Column(db.Float)
    last_updated_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    user = db.relationship("User", backref=db.backref("safety_sessions", lazy=True))
    updates = db.relationship("LocationUpdate", backref="safety_session", lazy=True, cascade="all, delete-orphan")


class LocationUpdate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    safety_session_id = db.Column(db.Integer, db.ForeignKey("safety_session.id"), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(120), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime)


def current_user():
    user_id = session.get("user_id")
    return db.session.get(User, user_id) if user_id else None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Please sign in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def responder_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user or user.role not in {"responder", "admin"}:
            flash("Responder access is required.", "danger")
            return redirect(url_for("index"))
        return view(*args, **kwargs)
    return wrapped


def allowed_file(name):
    return "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def expire_old_safety_sessions():
    expired = SafetySession.query.filter(SafetySession.is_active.is_(True), SafetySession.expires_at <= datetime.utcnow()).all()
    for item in expired:
        item.is_active = False
    if expired:
        db.session.commit()


def assistant_reply(message):
    """Local safety guidance for the academic prototype; it does not make emergency decisions."""
    text = (message or "").lower()
    if any(phrase in text for phrase in ["going to die", "want to die", "kill myself", "suicide", "shoot myself", "gun situation", "has a gun", "with a gun"]):
        return "I am concerned about your immediate safety. If there is a gun or you may harm yourself or someone else: move away from the weapon/person if you can do so safely; do not confront anyone; get to a safer or locked place and stay quiet; call 112 in Nigeria (or your local emergency number) now; and contact a trusted person with your exact location. If safe, activate SOS, but do not rely on this app instead of emergency services."
    if any(word in text for word in ["friend", "family", "someone else"]):
        return "If someone else may be in immediate danger, call 112 in Nigeria or the appropriate local emergency channel. Share only the facts you know and their last known location if it is safe to do so. You can submit an incident report, but do not put yourself at risk to collect information."
    if any(word in text for word in ["unsafe", "followed", "suspicious"]):
        return "Trust your instincts. Move toward a well-lit public place or people you trust, avoid confronting anyone suspicious, contact a trusted person, and use SOS if you need urgent assistance."
    if any(word in text for word in ["sos", "emergency", "danger", "help"]):
        return "If you are in immediate danger, move to a safer place if possible, activate SOS, and contact the official emergency/security channel available in your area. Do not wait for this app to guarantee a response."
    if any(word in text for word in ["report", "incident", "crime"]):
        return "Use New incident report to select the incident type, write only factual details, add an approximate location, and upload safe evidence if available. Do not confront suspects or expose other people’s private data."
    if any(word in text for word in ["location", "track", "map"]):
        return "Live Safety is voluntary and time-limited. Start it only when you want authorized responders to see your location, and stop it when you no longer need it. Exact locations are never placed on the public Safety Map."
    if any(word in text for word in ["anonymous", "privacy", "private"]):
        return "You may select anonymous reporting. Your report should still contain useful factual details, but avoid publishing names, phone numbers, or live locations in public spaces."
    return "I can help with SOS, reporting an incident, live location sharing, anonymous reports, and privacy. This is a safety guidance assistant, not a replacement for emergency services."


def incident_brief(item):
    priority = "High" if item.incident_type in {"Emergency SOS", "Kidnapping/abduction", "Armed robbery", "Violence"} else "Medium"
    return {
        "priority": priority,
        "summary": f"Case #{item.id}: {item.incident_type}. Current status: {item.status}.",
        "location": item.location_name or "Location supplied by device",
        "next_steps": [
            "Confirm the report is being reviewed by an authorized responder.",
            "Open the location in the map and assess the accuracy/timestamp.",
            "Use approved emergency or security channels to coordinate any response.",
            "Update the case status and keep sensitive details restricted."
        ]
    }


@app.context_processor
def inject_user():
    return {"user": current_user(), "incident_types": INCIDENT_TYPES}


@app.route("/")
def index():
    verified = Incident.query.filter_by(status="Verified").order_by(Incident.created_at.desc()).limit(8).all()
    return render_template("index.html", incidents=verified)


@app.route("/health")
def health():
    """A simple endpoint for deployment platforms to confirm the app is running."""
    return {"status": "ok", "service": "GuardianLink NG"}, 200


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["full_name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        if not name or not email or len(password) < 8:
            flash("Enter your name, email, and a password of at least 8 characters.", "danger")
        elif User.query.filter_by(email=email).first():
            flash("That email is already registered.", "danger")
        else:
            user = User(full_name=name, email=email, password_hash=generate_password_hash(password), trusted_contact=request.form.get("trusted_contact", "").strip())
            db.session.add(user); db.session.commit()
            flash("Account created. Please sign in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"].strip().lower()).first()
        if user and check_password_hash(user.password_hash, request.form["password"]):
            session["user_id"] = user.id
            flash("Welcome back.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "danger")
    return render_template("login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    reset_url = None
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            PasswordReset.query.filter_by(user_id=user.id, used_at=None).delete()
            item = PasswordReset(token=secrets.token_urlsafe(32), user_id=user.id, expires_at=datetime.utcnow() + timedelta(minutes=15))
            db.session.add(item); db.session.commit()
            # A real deployment should email this link through a configured email provider.
            reset_url = url_for("reset_password", token=item.token)
        flash("If this email is registered, a reset link has been created.", "success")
    return render_template("forgot_password.html", reset_url=reset_url)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    item = PasswordReset.query.filter_by(token=token, used_at=None).first()
    if not item or item.expires_at < datetime.utcnow():
        flash("This password-reset link is invalid or has expired. Request a new one.", "danger")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        password = request.form["password"]
        if len(password) < 8:
            flash("Use a password of at least 8 characters.", "danger")
        elif password != request.form["confirm_password"]:
            flash("The passwords do not match.", "danger")
        else:
            user = db.session.get(User, item.user_id)
            user.password_hash = generate_password_hash(password)
            item.used_at = datetime.utcnow()
            db.session.commit()
            flash("Password updated. You can now sign in.", "success")
            return redirect(url_for("login"))
    return render_template("reset_password.html")


@app.route("/logout")
def logout():
    session.clear(); flash("You have signed out.", "success")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    reports = Incident.query.filter_by(reporter_id=user.id).order_by(Incident.created_at.desc()).all()
    return render_template("dashboard.html", reports=reports)

@app.route("/safety-assistant")
@login_required
def safety_assistant():
    return render_template("safety_assistant.html")


@app.route("/safety-assistant/chat", methods=["POST"])
@login_required
def safety_assistant_chat():
    data = request.get_json(silent=True) or {}
    return jsonify({"reply": assistant_reply(data.get("message", ""))})


@app.route("/report", methods=["GET", "POST"])
@login_required
def report():
    if request.method == "POST":
        try:
            latitude, longitude = float(request.form["latitude"]), float(request.form["longitude"])
            if not (-90 <= latitude <= 90 and -180 <= longitude <= 180): raise ValueError
        except ValueError:
            flash("Use valid latitude and longitude values.", "danger")
            return render_template("report.html")
        evidence_name = None
        upload = request.files.get("evidence")
        if upload and upload.filename:
            if not allowed_file(upload.filename):
                flash("Evidence must be an image, PDF, or audio file.", "danger")
                return render_template("report.html")
            evidence_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secure_filename(upload.filename)}"
            upload.save(os.path.join(app.config["UPLOAD_FOLDER"], evidence_name))
        item = Incident(incident_type=request.form["incident_type"], description=request.form["description"].strip(), latitude=latitude, longitude=longitude, location_name=request.form.get("location_name", "").strip(), is_anonymous=bool(request.form.get("anonymous")), evidence_file=evidence_name, reporter_id=current_user().id)
        db.session.add(item); db.session.commit()
        flash(f"Report #{item.id} submitted securely. A responder will review it.", "success")
        return redirect(url_for("dashboard"))
    return render_template("report.html")


@app.route("/sos", methods=["POST"])
@login_required
def sos():
    try:
        latitude, longitude = float(request.form["latitude"]), float(request.form["longitude"])
    except (KeyError, ValueError):
        flash("Location was not available. Please allow location access and try again.", "danger")
        return redirect(url_for("dashboard"))
    item = Incident(incident_type="Emergency SOS", description="SOS activated by registered citizen. Treat as high priority.", latitude=latitude, longitude=longitude, location_name="Location supplied by device", reporter_id=current_user().id, status="Submitted")
    db.session.add(item); db.session.commit()
    flash(f"SOS #{item.id} recorded. In a production system, this would notify verified responders and your trusted contact.", "warning")
    return redirect(url_for("dashboard"))


@app.route("/responder")
@responder_required
def responder():
    reports = Incident.query.order_by(Incident.created_at.desc()).all()
    return render_template("responder.html", reports=reports, statuses=STATUSES)


@app.route("/admin-assistant/<int:incident_id>")
@responder_required
def admin_assistant(incident_id):
    item = db.session.get(Incident, incident_id)
    if not item:
        flash("Report not found.", "danger")
        return redirect(url_for("responder"))
    return render_template("admin_assistant.html", report=item, brief=incident_brief(item))


@app.route("/evidence/<path:filename>")
@responder_required
def evidence(filename):
    """Evidence is restricted to authorized responders and administrators."""
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=False)


@app.route("/responder/<int:incident_id>/status", methods=["POST"])
@responder_required
def update_status(incident_id):
    item = db.session.get(Incident, incident_id)
    status = request.form.get("status")
    if not item or status not in STATUSES:
        flash("Invalid report or status.", "danger")
    else:
        item.status = status; db.session.commit()
        flash(f"Report #{item.id} updated.", "success")
    return redirect(url_for("responder"))


@app.route("/safety-map")
def safety_map():
    # Only verified reports are public; coordinates are rounded to protect victims/reporters.
    reports = Incident.query.filter_by(status="Verified").all()
    markers = [{"id": x.id, "type": x.incident_type, "location": x.location_name or "General area", "lat": round(x.latitude, 2), "lng": round(x.longitude, 2), "date": x.created_at.strftime("%d %b %Y")} for x in reports]
    return render_template("map.html", markers=markers)


@app.route("/field-safety")
@login_required
def field_safety():
    expire_old_safety_sessions()
    active = SafetySession.query.filter_by(user_id=current_user().id, is_active=True).order_by(SafetySession.started_at.desc()).first()
    return render_template("field_safety.html", active_session=active)


@app.route("/field-safety/start", methods=["POST"])
@login_required
def start_safety_session():
    expire_old_safety_sessions()
    active = SafetySession.query.filter_by(user_id=current_user().id, is_active=True).first()
    if active:
        return jsonify({"ok": False, "message": "A safety session is already active."}), 400
    try:
        duration = int(request.form.get("duration", 30))
        latitude, longitude = float(request.form["latitude"]), float(request.form["longitude"])
        if duration not in {15, 30, 60} or not (-90 <= latitude <= 90 and -180 <= longitude <= 180): raise ValueError
    except (ValueError, KeyError):
        return jsonify({"ok": False, "message": "Invalid duration or location."}), 400
    now = datetime.utcnow()
    item = SafetySession(user_id=current_user().id, expires_at=now.replace(second=0, microsecond=0) + timedelta(minutes=duration), last_latitude=latitude, last_longitude=longitude, last_updated_at=now)
    db.session.add(item); db.session.flush()
    db.session.add(LocationUpdate(safety_session_id=item.id, latitude=latitude, longitude=longitude))
    db.session.commit()
    return jsonify({"ok": True, "session_id": item.id})


@app.route("/field-safety/<int:session_id>/update", methods=["POST"])
@login_required
def update_safety_session(session_id):
    item = db.session.get(SafetySession, session_id)
    if not item or item.user_id != current_user().id or not item.is_active or item.expires_at <= datetime.utcnow():
        return jsonify({"ok": False, "message": "Safety session is no longer active."}), 400
    data = request.get_json(silent=True) or request.form
    try:
        latitude, longitude = float(data["latitude"]), float(data["longitude"])
        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180): raise ValueError
    except (ValueError, KeyError, TypeError):
        return jsonify({"ok": False, "message": "Invalid location."}), 400
    item.last_latitude, item.last_longitude, item.last_updated_at = latitude, longitude, datetime.utcnow()
    db.session.add(LocationUpdate(safety_session_id=item.id, latitude=latitude, longitude=longitude))
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/field-safety/<int:session_id>/stop", methods=["POST"])
@login_required
def stop_safety_session(session_id):
    item = db.session.get(SafetySession, session_id)
    if not item or item.user_id != current_user().id:
        return jsonify({"ok": False, "message": "Safety session not found."}), 404
    item.is_active = False; db.session.commit()
    return jsonify({"ok": True})


@app.route("/commander-map")
@responder_required
def commander_map():
    expire_old_safety_sessions()
    items = SafetySession.query.filter_by(is_active=True).all()
    markers = [{"name": x.user.full_name, "role": x.user.role, "lat": x.last_latitude, "lng": x.last_longitude, "started": x.started_at.strftime("%H:%M"), "updated": x.last_updated_at.strftime("%H:%M:%S") if x.last_updated_at else "Never", "expires": x.expires_at.strftime("%H:%M")} for x in items if x.last_latitude is not None]
    return render_template("commander_map.html", markers=markers)


def seed_database():
    db.create_all()
    if not User.query.filter_by(email="admin@securealert.ng").first():
        admin = User(full_name="Demo Administrator", email="admin@securealert.ng", password_hash=generate_password_hash("Admin123!"), role="admin")
        responder = User(full_name="Demo Responder", email="responder@securealert.ng", password_hash=generate_password_hash("Responder123!"), role="responder")
        db.session.add_all([admin, responder]); db.session.commit()


def bootstrap_admin_from_environment():
    """Creates the first production admin only when both secret variables are configured."""
    email = os.environ.get("BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
    password = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "")
    if email and len(password) >= 8 and not User.query.filter_by(email=email).first():
        db.session.add(User(full_name="System Administrator", email=email, password_hash=generate_password_hash(password), role="admin"))
        db.session.commit()


with app.app_context():
    # Creates tables for the local demo. Production systems should use migrations.
    db.create_all()
    bootstrap_admin_from_environment()


if __name__ == "__main__":
    with app.app_context():
        seed_database()
    app.run(debug=True)
# @app.route("/offline-sos")
# def offline_sos():
#     # Directs offline SOS requests or fallback guidance to the field safety view
#     return redirect(url_for("field_safety"))