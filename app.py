from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response, g
from pymongo import MongoClient
from pymongo.errors import PyMongoError, DuplicateKeyError
from bson.objectid import ObjectId
from bson.errors import InvalidId
from datetime import datetime, timedelta
from functools import wraps
import os
import requests
import json
import webbrowser
import jwt
import csv
import io
import gridfs
from PIL import Image
from dotenv import load_dotenv
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'your-secret-key-change-this')

# API routes (used by the Flutter mobile app) are stateless/token-based, so they
# need CORS + a JWT secret distinct from the browser session cookie mechanism.
CORS(app, resources={r"/api/*": {"origins": "*"}})
JWT_SECRET = os.environ.get('JWT_SECRET', app.secret_key)

# --- SESSION COOKIE CONFIGURATION FOR LOCAL DEV ---
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # already default, keeps JS from accessing
    SESSION_COOKIE_SECURE=False,    # must be False on HTTP localhost
    SESSION_COOKIE_SAMESITE='Lax'   # prevents some CSRF warnings
)
app.config['MAX_CONTENT_LENGTH'] = 15 * 1024 * 1024  # 15MB cap on uploaded receipt photos

# ------------------ DATABASE CONNECTION ------------------
MONGODB_URI = os.environ.get('MONGODB_URI')
MONGODB_DB = os.environ.get('MONGODB_DB', 'Midiss')

_client = None

def get_db():
    """
    Return the MongoDB database handle, reusing a single MongoClient
    for the lifetime of the process (pymongo pools connections internally).
    """
    global _client
    try:
        if _client is None:
            _client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=8000)
        db = _client[MONGODB_DB]
        return db
    except PyMongoError as e:
        print(f"Error connecting to MongoDB: {e}")
        return None

def oid(value):
    """Safely convert a string/ObjectId to ObjectId, or return None if invalid."""
    if isinstance(value, ObjectId):
        return value
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        return None

def serialize(doc):
    """Add a string 'id' field (mirrors the old auto-increment int id) for template compatibility."""
    if doc is None:
        return None
    doc = dict(doc)
    doc['id'] = str(doc.pop('_id'))
    return doc

def _report_belongs_to_manager(db, report, manager_id):
    """True if the report's owner is an employee assigned to this manager."""
    owner = db.users.find_one({'_id': oid(report.get('user_id'))})
    return bool(owner) and owner.get('manager_id') == oid(manager_id)

def to_json_safe(doc):
    """
    Like serialize(), but for JSON API responses: every ObjectId becomes a
    string and every datetime becomes an ISO string, since jsonify() can't
    encode either type directly.
    """
    if doc is None:
        return None
    out = {}
    for key, value in dict(doc).items():
        if key == '_id':
            out['id'] = str(value)
        elif isinstance(value, ObjectId):
            out[key] = str(value)
        elif isinstance(value, datetime):
            out[key] = value.isoformat()
        else:
            out[key] = value
    return out

def log_audit(db, actor_id, actor_username, action, target=None, details=None):
    """
    Record a sensitive mutating action (approvals, employee management, etc.)
    for accountability — who did what, to whom, and when.
    """
    try:
        db.audit_log.insert_one({
            'actor_id': oid(actor_id),
            'actor_username': actor_username,
            'action': action,
            'target': target,
            'details': details or {},
            'created_at': datetime.utcnow()
        })
    except Exception as e:
        print("Audit log write failed:", e)

# ------------------ RECEIPT PHOTOS (GridFS) ------------------
def save_receipt_image(db, file_storage):
    """
    Resize/recompress an uploaded receipt photo before storing it in GridFS -
    Atlas's free tier only has 512MB total storage, so keeping each photo
    small (max 1600px, JPEG ~70% quality) matters.
    Returns the new file's ObjectId, or None if there's no usable file.
    """
    if not file_storage or not file_storage.filename:
        return None

    try:
        image = Image.open(file_storage.stream)
        image = image.convert('RGB')
        image.thumbnail((1600, 1600))

        buffer = io.BytesIO()
        image.save(buffer, format='JPEG', quality=70)
        buffer.seek(0)

        fs = gridfs.GridFS(db, collection='receipts')
        return fs.put(buffer.read(), content_type='image/jpeg', filename=file_storage.filename)
    except Exception as e:
        print("Receipt image save failed:", e)
        return None

def _can_view_receipt(db, owner_user_id, viewer_id, viewer_role):
    """True if viewer is the receipt's owner, or that owner's assigned manager."""
    if str(owner_user_id) == str(viewer_id):
        return True
    if viewer_role == 'manager':
        owner = db.users.find_one({'_id': oid(owner_user_id)})
        return bool(owner) and owner.get('manager_id') == oid(viewer_id)
    return False

# ------------------ API AUTH (JWT, for the Flutter app) ------------------
def generate_token(user):
    payload = {
        'user_id': str(user['_id']),
        'username': user['username'],
        'role': user['role'],
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header'}), 401
        token = auth_header.split(' ', 1)[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        g.user_id = payload['user_id']
        g.username = payload['username']
        g.role = payload['role']
        return f(*args, **kwargs)
    return wrapper

def manager_required(f):
    @wraps(f)
    def role_check(*args, **kwargs):
        if g.role != 'manager':
            return jsonify({'error': 'Manager role required'}), 403
        return f(*args, **kwargs)
    return token_required(role_check)

# ------------------ CURRENCY FUNCTIONS ------------------
def get_exchange_rates():
    """
    Fetch current exchange rates from API with caching in DB.
    Cached if updated within last 6 hours.
    """
    db = get_db()
    if db is None:
        return None

    try:
        cutoff = datetime.utcnow() - timedelta(hours=6)
        cached = db.exchange_rates.find_one(
            {'updated_at': {'$gt': cutoff}},
            sort=[('updated_at', -1)]
        )
        if cached:
            data = cached['rates_data']
            return data if isinstance(data, dict) else json.loads(data)

        # fetch from external API
        response = requests.get('https://open.er-api.com/v6/latest/USD', timeout=10)
        if response.status_code == 200:
            rates_data = response.json()
            db.exchange_rates.insert_one({
                'base_currency': 'USD',
                'rates_data': rates_data,
                'updated_at': datetime.utcnow()
            })
            return rates_data
        else:
            print(f"Exchange rate API returned status {response.status_code}")
            return None
    except Exception as e:
        print(f"Error fetching exchange rates: {e}")
        return None

def convert_to_usd(amount, from_currency):
    """
    Convert amount from `from_currency` to USD using cached or fresh rates.
    Returns (usd_amount, exchange_rate).
    """
    if from_currency == 'USD':
        return amount, 1.0

    rates_data = get_exchange_rates()
    if not rates_data:
        return None, None

    rates = rates_data.get('rates', {})
    if from_currency in rates:
        exchange_rate = rates[from_currency]
        # API gives price USD -> from_currency, so to convert from_currency to USD: amount / rate
        usd_amount = amount / exchange_rate
        return round(usd_amount, 2), round(1 / exchange_rate, 6)
    return None, None

def convert_currency(amount, from_currency, to_currency):
    """
    Convert amount from one currency to another via USD if needed.
    """
    if from_currency == to_currency:
        return round(amount, 2)

    rates_data = get_exchange_rates()
    if not rates_data:
        return round(amount, 2)

    rates = rates_data.get('rates', {})

    # Convert source to USD
    if from_currency == 'USD':
        usd_amount = amount
    else:
        if from_currency not in rates:
            return round(amount, 2)
        usd_amount = amount / rates[from_currency]

    # Convert USD to target
    if to_currency == 'USD':
        return round(usd_amount, 2)
    elif to_currency in rates:
        target_amount = usd_amount * rates[to_currency]
        return round(target_amount, 2)

    return round(amount, 2)

# ------------------ FLIGHTS (AviationStack, cached) ------------------
AVIATIONSTACK_API_KEY = os.environ.get('AVIATIONSTACK_API_KEY')
FLIGHT_CACHE_TTL_HOURS = 12
FLIGHT_CACHE_MONTHLY_CALL_LIMIT = 90  # AviationStack free tier allows 100/month - leave headroom

def refresh_flights_if_stale(db, force=False):
    """
    Refresh the cached 'current flights' list from AviationStack if the
    cache is older than FLIGHT_CACHE_TTL_HOURS (or force=True). Tracks a
    monthly call counter so we never approach the free tier's 100/month cap -
    refreshes are skipped (silently, serving stale data) once that's at risk.
    """
    if not AVIATIONSTACK_API_KEY:
        return

    meta = db.flight_cache_meta.find_one({'_id': 'singleton'}) or {}
    current_month = datetime.utcnow().strftime('%Y-%m')
    calls_this_month = meta.get('calls_this_month', 0) if meta.get('call_month') == current_month else 0

    last_fetched_at = meta.get('last_fetched_at')
    stale = not last_fetched_at or (datetime.utcnow() - last_fetched_at) > timedelta(hours=FLIGHT_CACHE_TTL_HOURS)
    if not (stale or force):
        return

    if calls_this_month >= FLIGHT_CACHE_MONTHLY_CALL_LIMIT:
        print(f"Flight cache refresh skipped: monthly call limit reached ({calls_this_month})")
        return

    try:
        response = requests.get(
            'http://api.aviationstack.com/v1/flights',
            params={'access_key': AVIATIONSTACK_API_KEY, 'limit': 100},
            timeout=25
        )
        response.raise_for_status()
        data = response.json().get('data', [])

        flight_docs = []
        for f in data:
            departure = f.get('departure') or {}
            arrival = f.get('arrival') or {}
            airline = f.get('airline') or {}
            flight = f.get('flight') or {}
            if not (departure.get('iata') and arrival.get('iata')):
                continue
            flight_docs.append({
                'flight_number': (flight.get('iata') or flight.get('number') or 'N/A').strip(),
                'airline_name': (airline.get('name') or 'Unknown Airline').strip(),
                'departure_airport': (departure.get('airport') or departure.get('iata') or '').strip(),
                'departure_iata': departure.get('iata'),
                'departure_scheduled': departure.get('scheduled'),
                'arrival_airport': (arrival.get('airport') or arrival.get('iata') or '').strip(),
                'arrival_iata': arrival.get('iata'),
                'arrival_scheduled': arrival.get('scheduled'),
                'status': f.get('flight_status') or 'scheduled',
                'fetched_at': datetime.utcnow()
            })

        if flight_docs:
            db.flights.delete_many({})
            db.flights.insert_many(flight_docs)

        db.flight_cache_meta.update_one(
            {'_id': 'singleton'},
            {'$set': {'last_fetched_at': datetime.utcnow(), 'calls_this_month': calls_this_month + 1, 'call_month': current_month}},
            upsert=True
        )
    except Exception as e:
        print("Flight cache refresh failed:", e)
        try:
            db.flight_cache_meta.update_one(
                {'_id': 'singleton'},
                {'$set': {'last_error': str(e), 'last_error_at': datetime.utcnow()}},
                upsert=True
            )
        except Exception:
            pass

def _create_expense_and_report(db, user_oid, destination, purpose, date_from, date_to,
                                currency, amount, receipt_file, client_name=None,
                                flight_number=None, airline_name=None):
    """
    Shared by the plain "Add Expense" flow and the "Book a Flight for a
    Client" flow - both end up creating the same expense+report pair, just
    with different origin data (typed in vs. pre-filled from a flight).
    """
    usd_amount, exchange_rate = convert_to_usd(amount, currency)
    if usd_amount is None:
        usd_amount = amount
        exchange_rate = 1.0

    receipt_file_id = save_receipt_image(db, receipt_file)

    expense_doc = {
        'user_id': user_oid,
        'destination': destination,
        'purpose': purpose,
        'date_from': date_from,
        'date_to': date_to,
        'currency': currency,
        'amount': amount,
        'usd_amount': usd_amount,
        'exchange_rate': exchange_rate,
        'status': 'pending',
        'receipt_file_id': receipt_file_id,
        'client_name': client_name,
        'flight_number': flight_number,
        'airline_name': airline_name,
        'created_at': datetime.utcnow()
    }
    result = db.expenses.insert_one(expense_doc)

    if client_name:
        report_title = f"{client_name} — {destination}" if destination else f"Booking for {client_name}"
    else:
        report_title = f"Travel to {destination}" if destination else "Expense Report"

    db.reports.insert_one({
        'user_id': user_oid,
        'title': report_title,
        'period_from': date_from,
        'period_to': date_to,
        'total_amount': amount,
        'usd_amount': usd_amount,
        'currency': currency,
        'status': 'pending',
        'manager_comment': None,
        'receipt_file_id': receipt_file_id,
        'client_name': client_name,
        'flight_number': flight_number,
        'airline_name': airline_name,
        'created_at': datetime.utcnow()
    })

    expense_doc['_id'] = result.inserted_id
    return expense_doc, usd_amount

# ------------------ DATABASE SETUP ------------------
def init_db():
    """
    Ensure indexes exist and insert default users.
    Mongo collections are created implicitly on first insert, so there's
    no CREATE TABLE step - just indexes + seed data.
    """
    db = get_db()
    if db is None:
        print("Failed to connect to database")
        return

    try:
        db.users.create_index('username', unique=True)
        db.audit_log.create_index('created_at')
        db.flights.create_index('departure_scheduled')

        if not db.users.find_one({'username': 'admin'}):
            db.users.insert_one({
                'username': 'admin',
                'password': generate_password_hash('admin123'),
                'email': 'admin@company.com',
                'role': 'manager',
                'manager_id': None
            })

        if not db.users.find_one({'username': 'employee'}):
            db.users.insert_one({
                'username': 'employee',
                'password': generate_password_hash('employee123'),
                'email': 'employee@company.com',
                'role': 'employee',
                'manager_id': None
            })
    except Exception as e:
        print("Error initializing DB:", e)

# ------------------ ROUTES ------------------

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('home_content.html')

# ---------- Authentication ----------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        db = get_db()
        if db is None:
            flash('Database connection error!', 'error')
            return render_template('login.html')

        try:
            candidate = db.users.find_one({'username': username})
            user = candidate if candidate and check_password_hash(candidate['password'], password) else None
        except Exception as e:
            print("Login query error:", e)
            user = None

        if user:
            # store manager_id (nullable) too so templates/routes can use it if needed
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['role'] = user['role']
            session['manager_id'] = str(user['manager_id']) if user.get('manager_id') else None
            flash('Login successful!', 'success')
            if user['role'] == 'manager':
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('employee_dashboard'))
        else:
            flash('Invalid username or password!', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()  # clears cookie
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ---------- API for exchange rates (frontend) ----------


@app.route('/get_exchange_rates', methods=['GET'])
def get_exchange_rates_api():
    rates_data = get_exchange_rates()
    data = rates_data['rates'] if rates_data and 'rates' in rates_data else {}
    return Response(
        response=json.dumps(data),
        status=200,
        mimetype='application/json;charset=utf-8'
    )

# ---------- Manager Dashboard ----------
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or session.get('role') != 'manager':
        return redirect(url_for('login'))

    db = get_db()
    if db is None:
        flash('Database connection error!', 'error')
        return redirect(url_for('login'))

    try:
        manager_oid = oid(session['user_id'])

        # employees for this manager (use manager_id filtering so manager sees only own employees)
        managed_employees = [
            serialize(e) for e in db.users.find(
                {'role': 'employee', 'manager_id': manager_oid},
                {'password': 0}
            )
        ]
        employee_ids = [oid(e['id']) for e in managed_employees]

        # pending reports count — only for this manager's own employees
        pending_reports_count = db.reports.count_documents({
            'status': 'pending',
            'user_id': {'$in': employee_ids}
        })

        # total expenses this month from approved reports (USD) — only this manager's employees
        now = datetime.utcnow()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        if month_start.month == 12:
            next_month_start = month_start.replace(year=month_start.year + 1, month=1)
        else:
            next_month_start = month_start.replace(month=month_start.month + 1)

        agg = list(db.reports.aggregate([
            {'$match': {
                'status': 'approved',
                'user_id': {'$in': employee_ids},
                'created_at': {'$gte': month_start, '$lt': next_month_start}
            }},
            {'$group': {'_id': None, 'total': {'$sum': '$usd_amount'}}}
        ]))
        total_expenses = agg[0]['total'] if agg else 0

        # recent reports — only this manager's own employees
        raw_reports = list(
            db.reports.find({'user_id': {'$in': employee_ids}})
            .sort('created_at', -1).limit(10)
        )
        users_by_id = {oid(e['id']): e for e in managed_employees}
        reports = []
        for r in raw_reports:
            r = serialize(r)
            owner = users_by_id.get(oid(r.get('user_id')))
            r['username'] = owner['username'] if owner else 'Unknown'
            reports.append(r)
    except Exception as e:
        print("Dashboard query error:", e)
        flash('Error loading dashboard data', 'error')
        reports = []
        pending_reports_count = 0
        total_expenses = 0
        managed_employees = []

    return render_template('dashboard.html',
                           pending_reports=pending_reports_count,
                           total_expenses=total_expenses,
                           reports=reports,
                           managed_employees=managed_employees)

# -# --------- Employee Dashboard ----------
@app.route('/employee_dashboard', methods=['GET', 'POST'])
def employee_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    if db is None:
        flash('Database connection error!', 'error')
        return redirect(url_for('login'))

    try:
        user_oid = oid(session['user_id'])

        # Get user's expenses, annotated with the status of any report for this user
        # (mirrors the original per-user join: not a strict per-expense link)
        user_reports = list(db.reports.find({'user_id': user_oid}))
        latest_report_status = user_reports[0]['status'] if user_reports else None

        raw_expenses = list(db.expenses.find({'user_id': user_oid}).sort('created_at', -1))
        expenses = []
        for e in raw_expenses:
            e = serialize(e)
            e['report_status'] = latest_report_status
            expenses.append(e)

        # Get user's reports
        reports = [serialize(r) for r in
                   db.reports.find({'user_id': user_oid}).sort('created_at', -1)]

        # Current exchange rates
        rates_data = get_exchange_rates()
        current_rates = rates_data.get('rates', {}) if rates_data else {}

        return render_template(
            'employee_dashboard.html',
            expenses=expenses,
            reports=reports,
            exchange_rates=current_rates,
            session=session
        )

    except Exception as e:
        print("Employee dashboard error:", e)
        flash('Error loading employee dashboard', 'error')
        return render_template(
            'employee_dashboard.html',
            expenses=[],
            reports=[],
            exchange_rates={},
            session=session
        )


# ---------- Add Expense ----------
@app.route('/add_expense', methods=['POST'])
def add_expense():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Get form inputs safely
    destination = request.form.get('destination', '').strip()
    purpose = request.form.get('purpose', '').strip()
    date_from = request.form.get('date_from') or None
    date_to = request.form.get('date_to') or None
    currency = request.form.get('local_currency', 'USD').strip()   # matches the form select name
    amount_raw = request.form.get('local_amount', '0').strip()

    try:
        amount = float(amount_raw) if amount_raw else 0.0
    except ValueError:
        flash('Invalid amount provided', 'error')
        return redirect(url_for('employee_dashboard'))

    db = get_db()
    if db is None:
        flash('Database connection error!', 'error')
        return redirect(url_for('employee_dashboard'))

    try:
        user_oid = oid(session['user_id'])
        _, usd_amount = _create_expense_and_report(
            db, user_oid, destination, purpose, date_from, date_to,
            currency, amount, request.files.get('receipt')
        )
        flash(f'Expense added successfully! Original: {amount} {currency}, USD: ${usd_amount}', 'success')

    except Exception as e:
        print("Add expense error:", e)
        flash(f'Error adding expense: {e}', 'error')

    return redirect(url_for('employee_dashboard'))

# ---------- Receipt photo ----------
@app.route('/expenses/<expense_id>/receipt')
def view_receipt(expense_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    if db is None:
        return ('Database connection error', 503)

    expense = db.expenses.find_one({'_id': oid(expense_id)})
    if not expense or not expense.get('receipt_file_id'):
        return ('Receipt not found', 404)

    if not _can_view_receipt(db, expense['user_id'], session['user_id'], session.get('role')):
        return ('Not authorized', 403)

    fs = gridfs.GridFS(db, collection='receipts')
    grid_file = fs.get(expense['receipt_file_id'])
    return Response(grid_file.read(), mimetype=grid_file.content_type or 'image/jpeg')

@app.route('/reports/<report_id>/receipt')
def view_report_receipt(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    if db is None:
        return ('Database connection error', 503)

    report = db.reports.find_one({'_id': oid(report_id)})
    if not report or not report.get('receipt_file_id'):
        return ('Receipt not found', 404)

    if not _can_view_receipt(db, report['user_id'], session['user_id'], session.get('role')):
        return ('Not authorized', 403)

    fs = gridfs.GridFS(db, collection='receipts')
    grid_file = fs.get(report['receipt_file_id'])
    return Response(grid_file.read(), mimetype=grid_file.content_type or 'image/jpeg')

# ---------- Flights (agency-style client bookings) ----------
def _flight_booking_counts(db, manager_oid):
    """For each flight_number, how many of this manager's employees' clients booked it, and who."""
    managed_employees = list(db.users.find({'role': 'employee', 'manager_id': manager_oid}, {'username': 1}))
    employee_ids = [e['_id'] for e in managed_employees]
    employees_by_id = {e['_id']: e['username'] for e in managed_employees}

    counts = {}
    for r in db.reports.find({'user_id': {'$in': employee_ids}, 'flight_number': {'$ne': None}}):
        fn = r['flight_number']
        counts.setdefault(fn, {'count': 0, 'details': []})
        counts[fn]['count'] += 1
        counts[fn]['details'].append({
            'employee': employees_by_id.get(r['user_id'], 'Unknown'),
            'client_name': r.get('client_name') or 'Unknown client'
        })
    return counts

@app.route('/flights')
def flights_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    if db is None:
        flash('Database connection error!', 'error')
        return redirect(url_for('home'))

    refresh_flights_if_stale(db)
    flights = [serialize(f) for f in db.flights.find().sort('departure_scheduled', 1)]

    booking_counts = {}
    if session.get('role') == 'manager':
        booking_counts = _flight_booking_counts(db, oid(session['user_id']))

    return render_template(
        'flights.html',
        flights=flights,
        booking_counts=booking_counts,
        has_api_key=bool(AVIATIONSTACK_API_KEY)
    )

@app.route('/flights/refresh', methods=['POST'])
def refresh_flights_now():
    if 'user_id' not in session or session.get('role') != 'manager':
        return redirect(url_for('login'))
    db = get_db()
    if db is not None:
        refresh_flights_if_stale(db, force=True)
        flash('Flights refreshed.', 'success')
    return redirect(url_for('flights_page'))

@app.route('/flights/<flight_id>/book', methods=['GET', 'POST'])
def book_flight(flight_id):
    if 'user_id' not in session or session.get('role') != 'employee':
        return redirect(url_for('login'))

    db = get_db()
    if db is None:
        flash('Database connection error!', 'error')
        return redirect(url_for('flights_page'))

    flight = db.flights.find_one({'_id': oid(flight_id)})
    if not flight:
        flash('That flight is no longer in the current list.', 'error')
        return redirect(url_for('flights_page'))

    if request.method == 'POST':
        client_name = request.form.get('client_name', '').strip()
        purpose = request.form.get('purpose', '').strip()
        currency = request.form.get('local_currency', 'USD').strip()
        amount_raw = request.form.get('local_amount', '0').strip()

        if not client_name:
            flash('Client name is required', 'error')
            return redirect(url_for('book_flight', flight_id=flight_id))

        try:
            amount = float(amount_raw) if amount_raw else 0.0
        except ValueError:
            flash('Invalid amount provided', 'error')
            return redirect(url_for('book_flight', flight_id=flight_id))

        destination = flight.get('arrival_airport') or flight.get('arrival_iata')
        date_from = (flight.get('departure_scheduled') or '')[:10] or None
        date_to = (flight.get('arrival_scheduled') or '')[:10] or None

        try:
            user_oid = oid(session['user_id'])
            _, usd_amount = _create_expense_and_report(
                db, user_oid, destination, purpose, date_from, date_to,
                currency, amount, request.files.get('receipt'),
                client_name=client_name,
                flight_number=flight.get('flight_number'),
                airline_name=flight.get('airline_name')
            )
            flash(f'Booked {flight.get("flight_number")} for {client_name}! USD: ${usd_amount}', 'success')
        except Exception as e:
            print("Book flight error:", e)
            flash(f'Error booking flight: {e}', 'error')

        return redirect(url_for('employee_dashboard'))

    return render_template('book_flight.html', flight=serialize(flight))

# ---------- Currency converter page ----------
@app.route('/currency_converter')
def currency_converter():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    rates_data = get_exchange_rates()
    return render_template('currency_converter.html', rates_data=rates_data)

@app.route('/convert_currency', methods=['POST'])
def convert_currency_api():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        amount = float(request.form.get('amount', '0'))
    except ValueError:
        return jsonify({'error': 'Invalid amount'}), 400

    from_currency = request.form.get('from_currency', 'USD').strip()
    to_currency = request.form.get('to_currency', 'USD').strip()

    converted_amount = convert_currency(amount, from_currency, to_currency)

    return jsonify({
        'original_amount': amount,
        'from_currency': from_currency,
        'to_currency': to_currency,
        'converted_amount': converted_amount
    })

# ---------- Manage Employees (Manager only) ----------
@app.route('/manage_employees')
def manage_employees():
    if 'user_id' not in session or session.get('role') != 'manager':
        return redirect(url_for('login'))

    db = get_db()
    if db is None:
        flash('Database connection error!', 'error')
        return redirect(url_for('dashboard'))

    try:
        manager_oid = oid(session['user_id'])
        # Show only employees that belong to this manager
        employees = [serialize(e) for e in
                     db.users.find({'role': 'employee', 'manager_id': manager_oid})]
    except Exception as e:
        print("Manage employees error:", e)
        employees = []
        flash('Error loading employees', 'error')

    return render_template('manage_employees.html', employees=employees)

@app.route('/add_employee', methods=['POST'])
def add_employee():
    if 'user_id' not in session or session.get('role') != 'manager':
        return redirect(url_for('login'))

    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    role = request.form.get('role', 'employee').strip()

    db = get_db()
    if db is None:
        flash('Database connection error!', 'error')
        return redirect(url_for('manage_employees'))

    try:
        # Set manager_id to current manager for employees
        manager_id_value = oid(session['user_id']) if role == 'employee' else None
        result = db.users.insert_one({
            'username': username,
            'password': generate_password_hash(password),
            'email': email,
            'role': role,
            'manager_id': manager_id_value
        })
        log_audit(db, session['user_id'], session['username'], 'add_employee',
                  target=str(result.inserted_id), details={'username': username, 'role': role})
        flash(f'Employee {username} added successfully!', 'success')
    except DuplicateKeyError:
        flash('Username already exists!', 'error')
    except Exception as e:
        print("Add employee error:", e)
        flash('Error adding employee', 'error')

    return redirect(url_for('manage_employees'))

@app.route('/edit_employee', methods=['POST'])
def edit_employee():
    if 'user_id' not in session or session.get('role') != 'manager':
        return redirect(url_for('login'))

    employee_id = request.form.get('employee_id')
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    role = request.form.get('role', 'employee').strip()
    password = request.form.get('password', None)

    db = get_db()
    if db is None:
        flash('Database connection error!', 'error')
        return redirect(url_for('manage_employees'))

    try:
        employee_oid = oid(employee_id)

        # Verify employee exists and belongs to this manager
        owner = db.users.find_one({'_id': employee_oid})
        if not owner:
            flash('Employee not found!', 'error')
            return redirect(url_for('manage_employees'))

        manager_id_of_employee = owner.get('manager_id')
        if manager_id_of_employee is not None and str(manager_id_of_employee) != session['user_id']:
            flash('You are not authorized to edit this employee!', 'error')
            return redirect(url_for('manage_employees'))

        # Update employee with proper manager_id handling
        update_fields = {'username': username, 'email': email, 'role': role}
        if password:
            update_fields['password'] = generate_password_hash(password)

        if role == 'employee':
            update_fields['manager_id'] = oid(session['user_id'])
        else:  # role is manager → manager_id should be NULL
            update_fields['manager_id'] = None

        db.users.update_one({'_id': employee_oid}, {'$set': update_fields})
        log_audit(db, session['user_id'], session['username'], 'edit_employee',
                  target=employee_id, details={'username': username, 'role': role, 'password_changed': bool(password)})
        flash(f'Employee {username} updated successfully!', 'success')

    except Exception as e:
        print("Edit employee error:", e)
        flash('Error updating employee', 'error')

    return redirect(url_for('manage_employees'))

@app.route('/delete_employee', methods=['POST'])
def delete_employee():
    if 'user_id' not in session or session.get('role') != 'manager':
        return redirect(url_for('login'))

    employee_id = request.form.get('employee_id')

    db = get_db()
    if db is None:
        flash('Database connection error!', 'error')
        return redirect(url_for('manage_employees'))

    try:
        employee_oid = oid(employee_id)

        # Verify employee exists and belongs to this manager
        owner = db.users.find_one({'_id': employee_oid})
        if not owner:
            flash('Employee not found!', 'error')
            return redirect(url_for('manage_employees'))

        manager_id_of_employee = owner.get('manager_id')
        if manager_id_of_employee is not None and str(manager_id_of_employee) != session['user_id']:
            flash('You are not authorized to delete this employee!', 'error')
            return redirect(url_for('manage_employees'))

        # Delete employee (cascade: also remove their expenses/reports)
        db.users.delete_one({'_id': employee_oid})
        db.expenses.delete_many({'user_id': employee_oid})
        db.reports.delete_many({'user_id': employee_oid})
        log_audit(db, session['user_id'], session['username'], 'delete_employee',
                  target=employee_id, details={'username': owner.get('username')})
        flash('Employee deleted successfully!', 'success')

    except Exception as e:
        print("Delete employee error:", e)
        flash('Error deleting employee', 'error')

    return redirect(url_for('manage_employees'))

# ---------- Reports (list for manager or employee) ----------
@app.route('/reports')
def reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    if db is None:
        flash('Database connection error!', 'error')
        return redirect(url_for('login'))

    try:
        if session.get('role') == 'manager':
            # manager sees only reports from employees assigned to them
            manager_oid = oid(session['user_id'])
            managed_employees = list(db.users.find(
                {'role': 'employee', 'manager_id': manager_oid}, {'password': 0}
            ))
            employee_ids = [e['_id'] for e in managed_employees]
            users_by_id = {e['_id']: e for e in managed_employees}

            raw_reports = list(db.reports.find({'user_id': {'$in': employee_ids}}).sort('created_at', -1))
            reports_data = []
            for r in raw_reports:
                r = serialize(r)
                owner = users_by_id.get(oid(r.get('user_id')))
                r['employee_name'] = owner['username'] if owner else 'Unknown'
                reports_data.append(r)
        else:
            user_oid = oid(session['user_id'])
            reports_data = [serialize(r) for r in
                            db.reports.find({'user_id': user_oid}).sort('created_at', -1)]
    except Exception as e:
        print("Reports fetch error:", e)
        flash('Error loading reports', 'error')
        reports_data = []

    return render_template('reports.html', reports=reports_data)

@app.route('/approve_report/<report_id>')
def approve_report(report_id):
    if 'user_id' not in session or session.get('role') != 'manager':
        return redirect(url_for('login'))

    db = get_db()
    if db is None:
        flash('Database connection error!', 'error')
        return redirect(url_for('reports'))

    try:
        report = db.reports.find_one({'_id': oid(report_id)})
        if not report or not _report_belongs_to_manager(db, report, session['user_id']):
            flash('You are not authorized to approve this report!', 'error')
            return redirect(url_for('reports'))

        db.reports.update_one({'_id': oid(report_id)}, {'$set': {'status': 'approved'}})
        log_audit(db, session['user_id'], session['username'], 'approve_report', target=report_id)
        flash('Report approved successfully!', 'success')
    except Exception as e:
        print("Approve report error:", e)
        flash('Error approving report', 'error')

    return redirect(url_for('reports'))

@app.route('/decline_report', methods=['POST'])
def decline_report():
    if 'user_id' not in session or session.get('role') != 'manager':
        return redirect(url_for('login'))

    report_id = request.form.get('report_id')
    comment = request.form.get('comment', '')

    db = get_db()
    if db is None:
        flash('Database connection error!', 'error')
        return redirect(url_for('reports'))

    try:
        report = db.reports.find_one({'_id': oid(report_id)})
        if not report or not _report_belongs_to_manager(db, report, session['user_id']):
            flash('You are not authorized to decline this report!', 'error')
            return redirect(url_for('reports'))

        db.reports.update_one(
            {'_id': oid(report_id)},
            {'$set': {'status': 'declined', 'manager_comment': comment}}
        )
        log_audit(db, session['user_id'], session['username'], 'decline_report',
                  target=report_id, details={'comment': comment})
        flash(f'Report declined. Reason: {comment}', 'info')
    except Exception as e:
        print("Decline report error:", e)
        flash('Error declining report', 'error')

    return redirect(url_for('reports'))

# ---------- Analytics (manager only) ----------
def _compute_analytics(db, manager_oid):
    """
    Three breakdowns scoped to this manager's own employees:
    monthly approved-spend trend, spend by employee, and spend by
    destination (from expenses, since that's where destination lives).
    """
    employee_ids = [e['_id'] for e in
                    db.users.find({'role': 'employee', 'manager_id': manager_oid}, {'_id': 1})]
    employees_by_id = {e['_id']: e['username'] for e in
                        db.users.find({'_id': {'$in': employee_ids}}, {'username': 1})}

    twelve_months_ago = datetime.utcnow() - timedelta(days=365)

    monthly_trend = list(db.reports.aggregate([
        {'$match': {'status': 'approved', 'user_id': {'$in': employee_ids},
                    'created_at': {'$gte': twelve_months_ago}}},
        {'$group': {
            '_id': {'year': {'$year': '$created_at'}, 'month': {'$month': '$created_at'}},
            'total': {'$sum': '$usd_amount'}
        }},
        {'$sort': {'_id.year': 1, '_id.month': 1}}
    ]))
    monthly_labels = [f"{m['_id']['year']}-{m['_id']['month']:02d}" for m in monthly_trend]
    monthly_totals = [round(m['total'], 2) for m in monthly_trend]

    by_employee_raw = list(db.reports.aggregate([
        {'$match': {'status': 'approved', 'user_id': {'$in': employee_ids}}},
        {'$group': {'_id': '$user_id', 'total': {'$sum': '$usd_amount'}}},
        {'$sort': {'total': -1}}
    ]))
    by_employee_labels = [employees_by_id.get(r['_id'], 'Unknown') for r in by_employee_raw]
    by_employee_totals = [round(r['total'], 2) for r in by_employee_raw]

    by_destination_raw = list(db.expenses.aggregate([
        {'$match': {'user_id': {'$in': employee_ids}}},
        {'$group': {'_id': '$destination', 'total': {'$sum': '$usd_amount'}}},
        {'$sort': {'total': -1}},
        {'$limit': 10}
    ]))
    by_destination_labels = [r['_id'] or 'Unknown' for r in by_destination_raw]
    by_destination_totals = [round(r['total'], 2) for r in by_destination_raw]

    return {
        'monthly_labels': monthly_labels,
        'monthly_totals': monthly_totals,
        'by_employee_labels': by_employee_labels,
        'by_employee_totals': by_employee_totals,
        'by_destination_labels': by_destination_labels,
        'by_destination_totals': by_destination_totals,
    }

@app.route('/analytics')
def analytics_page():
    if 'user_id' not in session or session.get('role') != 'manager':
        return redirect(url_for('login'))

    db = get_db()
    if db is None:
        flash('Database connection error!', 'error')
        return redirect(url_for('dashboard'))

    data = _compute_analytics(db, oid(session['user_id']))
    return render_template('analytics.html', data=data)

# ---------- Export reports as CSV ----------
@app.route('/reports/export.csv')
def export_reports_csv():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    if db is None:
        flash('Database connection error!', 'error')
        return redirect(url_for('reports'))

    if session.get('role') == 'manager':
        manager_oid = oid(session['user_id'])
        employee_ids = [e['_id'] for e in
                        db.users.find({'role': 'employee', 'manager_id': manager_oid}, {'_id': 1})]
        employees_by_id = {e['_id']: e['username'] for e in
                            db.users.find({'_id': {'$in': employee_ids}}, {'username': 1})}
        raw_reports = db.reports.find({'user_id': {'$in': employee_ids}}).sort('created_at', -1)
    else:
        user_oid = oid(session['user_id'])
        employees_by_id = {}
        raw_reports = db.reports.find({'user_id': user_oid}).sort('created_at', -1)

    output = io.StringIO()
    writer = csv.writer(output)
    header = ['Title', 'Period From', 'Period To', 'Amount', 'Currency', 'USD Amount', 'Status', 'Created At']
    if session.get('role') == 'manager':
        header.insert(0, 'Employee')
    writer.writerow(header)

    for r in raw_reports:
        row = [
            r.get('title', 'Expense Report'),
            r.get('period_from', ''),
            r.get('period_to', ''),
            r.get('total_amount', ''),
            r.get('currency', 'USD'),
            r.get('usd_amount', ''),
            r.get('status', 'pending'),
            r.get('created_at', ''),
        ]
        if session.get('role') == 'manager':
            row.insert(0, employees_by_id.get(r.get('user_id'), 'Unknown'))
        writer.writerow(row)

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=reports_export.csv'}
    )

# ---------- Audit Log (manager only) ----------
@app.route('/audit_log')
def audit_log_page():
    if 'user_id' not in session or session.get('role') != 'manager':
        return redirect(url_for('login'))

    db = get_db()
    if db is None:
        flash('Database connection error!', 'error')
        return redirect(url_for('dashboard'))

    manager_oid = oid(session['user_id'])
    entries = [serialize(e) for e in
               db.audit_log.find({'actor_id': manager_oid}).sort('created_at', -1).limit(200)]
    return render_template('audit_log.html', entries=entries)

# ==================================================================
# JSON API (token-auth) — used by the Flutter mobile app.
# Mirrors the web routes above but is stateless (JWT instead of session
# cookies) and returns JSON instead of rendered HTML.
# ==================================================================

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True) or request.form
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()

    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503

    candidate = db.users.find_one({'username': username})
    user = candidate if candidate and check_password_hash(candidate['password'], password) else None
    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401

    token = generate_token(user)
    return jsonify({
        'token': token,
        'user': {
            'id': str(user['_id']),
            'username': user['username'],
            'email': user.get('email'),
            'role': user['role'],
            'manager_id': str(user['manager_id']) if user.get('manager_id') else None
        }
    })

@app.route('/api/exchange_rates', methods=['GET'])
@token_required
def api_exchange_rates():
    rates_data = get_exchange_rates()
    return jsonify(rates_data.get('rates', {}) if rates_data else {})

@app.route('/api/dashboard', methods=['GET'])
@manager_required
def api_dashboard():
    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503

    manager_oid = oid(g.user_id)
    managed_employees = [
        to_json_safe(e) for e in db.users.find(
            {'role': 'employee', 'manager_id': manager_oid}, {'password': 0}
        )
    ]
    employee_ids = [oid(e['id']) for e in managed_employees]

    pending_reports_count = db.reports.count_documents({
        'status': 'pending', 'user_id': {'$in': employee_ids}
    })

    now = datetime.utcnow()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if month_start.month == 12:
        next_month_start = month_start.replace(year=month_start.year + 1, month=1)
    else:
        next_month_start = month_start.replace(month=month_start.month + 1)

    agg = list(db.reports.aggregate([
        {'$match': {
            'status': 'approved',
            'user_id': {'$in': employee_ids},
            'created_at': {'$gte': month_start, '$lt': next_month_start}
        }},
        {'$group': {'_id': None, 'total': {'$sum': '$usd_amount'}}}
    ]))
    total_expenses = agg[0]['total'] if agg else 0

    raw_reports = list(
        db.reports.find({'user_id': {'$in': employee_ids}}).sort('created_at', -1).limit(10)
    )
    users_by_id = {oid(e['id']): e for e in managed_employees}
    reports = []
    for r in raw_reports:
        r = to_json_safe(r)
        owner = users_by_id.get(oid(r.get('user_id')))
        r['username'] = owner['username'] if owner else 'Unknown'
        reports.append(r)

    return jsonify({
        'pending_reports': pending_reports_count,
        'total_expenses': total_expenses,
        'reports': reports,
        'managed_employees': managed_employees
    })

@app.route('/api/analytics', methods=['GET'])
@manager_required
def api_analytics():
    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503
    return jsonify(_compute_analytics(db, oid(g.user_id)))

@app.route('/api/flights', methods=['GET'])
@token_required
def api_flights():
    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503

    refresh_flights_if_stale(db)
    flights = [to_json_safe(f) for f in db.flights.find().sort('departure_scheduled', 1)]

    booking_counts = {}
    if g.role == 'manager':
        booking_counts = _flight_booking_counts(db, oid(g.user_id))

    return jsonify({'flights': flights, 'booking_counts': booking_counts})

@app.route('/api/flights/<flight_id>/book', methods=['POST'])
@token_required
def api_book_flight(flight_id):
    if g.role != 'employee':
        return jsonify({'error': 'Only employees can book flights'}), 403

    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503

    flight = db.flights.find_one({'_id': oid(flight_id)})
    if not flight:
        return jsonify({'error': 'That flight is no longer in the current list'}), 404

    data = request.get_json(silent=True) or request.form
    client_name = (data.get('client_name') or '').strip()
    purpose = (data.get('purpose') or '').strip()
    currency = (data.get('currency') or 'USD').strip()

    if not client_name:
        return jsonify({'error': 'Client name is required'}), 400

    try:
        amount = float(data.get('amount') or 0)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount provided'}), 400

    destination = flight.get('arrival_airport') or flight.get('arrival_iata')
    date_from = (flight.get('departure_scheduled') or '')[:10] or None
    date_to = (flight.get('arrival_scheduled') or '')[:10] or None

    user_oid = oid(g.user_id)
    expense_doc, usd_amount = _create_expense_and_report(
        db, user_oid, destination, purpose, date_from, date_to,
        currency, amount, request.files.get('receipt'),
        client_name=client_name,
        flight_number=flight.get('flight_number'),
        airline_name=flight.get('airline_name')
    )
    return jsonify({'message': 'Flight booked successfully', 'expense': to_json_safe(expense_doc)}), 201

@app.route('/api/employee_dashboard', methods=['GET'])
@token_required
def api_employee_dashboard():
    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503

    user_oid = oid(g.user_id)
    user_reports = list(db.reports.find({'user_id': user_oid}))
    latest_report_status = user_reports[0]['status'] if user_reports else None

    expenses = []
    for e in db.expenses.find({'user_id': user_oid}).sort('created_at', -1):
        e = to_json_safe(e)
        e['report_status'] = latest_report_status
        expenses.append(e)

    reports = [to_json_safe(r) for r in
               db.reports.find({'user_id': user_oid}).sort('created_at', -1)]

    rates_data = get_exchange_rates()
    current_rates = rates_data.get('rates', {}) if rates_data else {}

    return jsonify({
        'expenses': expenses,
        'reports': reports,
        'exchange_rates': current_rates
    })

@app.route('/api/expenses', methods=['POST'])
@token_required
def api_add_expense():
    data = request.get_json(silent=True) or request.form

    destination = (data.get('destination') or '').strip()
    purpose = (data.get('purpose') or '').strip()
    date_from = data.get('date_from') or None
    date_to = data.get('date_to') or None
    currency = (data.get('currency') or 'USD').strip()

    try:
        amount = float(data.get('amount') or 0)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount provided'}), 400

    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503

    user_oid = oid(g.user_id)
    expense_doc, usd_amount = _create_expense_and_report(
        db, user_oid, destination, purpose, date_from, date_to,
        currency, amount, request.files.get('receipt')
    )
    return jsonify({'message': 'Expense added successfully', 'expense': to_json_safe(expense_doc)}), 201

@app.route('/api/expenses/<expense_id>/receipt', methods=['GET'])
@token_required
def api_view_receipt(expense_id):
    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503

    expense = db.expenses.find_one({'_id': oid(expense_id)})
    if not expense or not expense.get('receipt_file_id'):
        return jsonify({'error': 'Receipt not found'}), 404

    if not _can_view_receipt(db, expense['user_id'], g.user_id, g.role):
        return jsonify({'error': 'Not authorized'}), 403

    fs = gridfs.GridFS(db, collection='receipts')
    grid_file = fs.get(expense['receipt_file_id'])
    return Response(grid_file.read(), mimetype=grid_file.content_type or 'image/jpeg')

@app.route('/api/reports/<report_id>/receipt', methods=['GET'])
@token_required
def api_view_report_receipt(report_id):
    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503

    report = db.reports.find_one({'_id': oid(report_id)})
    if not report or not report.get('receipt_file_id'):
        return jsonify({'error': 'Receipt not found'}), 404

    if not _can_view_receipt(db, report['user_id'], g.user_id, g.role):
        return jsonify({'error': 'Not authorized'}), 403

    fs = gridfs.GridFS(db, collection='receipts')
    grid_file = fs.get(report['receipt_file_id'])
    return Response(grid_file.read(), mimetype=grid_file.content_type or 'image/jpeg')

@app.route('/api/reports', methods=['GET'])
@token_required
def api_reports():
    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503

    if g.role == 'manager':
        manager_oid = oid(g.user_id)
        managed_employees = list(db.users.find(
            {'role': 'employee', 'manager_id': manager_oid}, {'password': 0}
        ))
        employee_ids = [e['_id'] for e in managed_employees]
        users_by_id = {e['_id']: e for e in managed_employees}

        raw_reports = list(db.reports.find({'user_id': {'$in': employee_ids}}).sort('created_at', -1))
        reports_data = []
        for r in raw_reports:
            r = to_json_safe(r)
            owner = users_by_id.get(oid(r.get('user_id')))
            r['employee_name'] = owner['username'] if owner else 'Unknown'
            reports_data.append(r)
    else:
        user_oid = oid(g.user_id)
        reports_data = [to_json_safe(r) for r in
                        db.reports.find({'user_id': user_oid}).sort('created_at', -1)]

    return jsonify(reports_data)

@app.route('/api/reports/<report_id>/approve', methods=['POST'])
@manager_required
def api_approve_report(report_id):
    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503

    report = db.reports.find_one({'_id': oid(report_id)})
    if not report or not _report_belongs_to_manager(db, report, g.user_id):
        return jsonify({'error': 'Not authorized to approve this report'}), 403

    db.reports.update_one({'_id': oid(report_id)}, {'$set': {'status': 'approved'}})
    log_audit(db, g.user_id, g.username, 'approve_report', target=report_id)
    return jsonify({'message': 'Report approved successfully'})

@app.route('/api/reports/<report_id>/decline', methods=['POST'])
@manager_required
def api_decline_report(report_id):
    data = request.get_json(silent=True) or request.form
    comment = data.get('comment', '')

    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503

    report = db.reports.find_one({'_id': oid(report_id)})
    if not report or not _report_belongs_to_manager(db, report, g.user_id):
        return jsonify({'error': 'Not authorized to decline this report'}), 403

    db.reports.update_one(
        {'_id': oid(report_id)},
        {'$set': {'status': 'declined', 'manager_comment': comment}}
    )
    log_audit(db, g.user_id, g.username, 'decline_report', target=report_id, details={'comment': comment})
    return jsonify({'message': f'Report declined. Reason: {comment}'})

@app.route('/api/employees', methods=['GET'])
@manager_required
def api_list_employees():
    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503

    manager_oid = oid(g.user_id)
    employees = [to_json_safe(e) for e in
                 db.users.find({'role': 'employee', 'manager_id': manager_oid}, {'password': 0})]
    return jsonify(employees)

@app.route('/api/audit_log', methods=['GET'])
@manager_required
def api_audit_log():
    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503

    manager_oid = oid(g.user_id)
    entries = [to_json_safe(e) for e in
               db.audit_log.find({'actor_id': manager_oid}).sort('created_at', -1).limit(200)]
    return jsonify(entries)

@app.route('/api/employees', methods=['POST'])
@manager_required
def api_add_employee():
    data = request.get_json(silent=True) or request.form
    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip()
    password = (data.get('password') or '').strip()
    role = (data.get('role') or 'employee').strip()

    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503

    try:
        manager_id_value = oid(g.user_id) if role == 'employee' else None
        result = db.users.insert_one({
            'username': username,
            'password': generate_password_hash(password),
            'email': email,
            'role': role,
            'manager_id': manager_id_value
        })
        log_audit(db, g.user_id, g.username, 'add_employee',
                  target=str(result.inserted_id), details={'username': username, 'role': role})
        return jsonify({'message': f'Employee {username} added successfully', 'id': str(result.inserted_id)}), 201
    except DuplicateKeyError:
        return jsonify({'error': 'Username already exists'}), 409

@app.route('/api/employees/<employee_id>', methods=['PUT'])
@manager_required
def api_edit_employee(employee_id):
    data = request.get_json(silent=True) or request.form
    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip()
    role = (data.get('role') or 'employee').strip()
    password = data.get('password')

    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503

    employee_oid = oid(employee_id)
    owner = db.users.find_one({'_id': employee_oid})
    if not owner:
        return jsonify({'error': 'Employee not found'}), 404

    manager_id_of_employee = owner.get('manager_id')
    if manager_id_of_employee is not None and str(manager_id_of_employee) != g.user_id:
        return jsonify({'error': 'Not authorized to edit this employee'}), 403

    update_fields = {'username': username, 'email': email, 'role': role}
    if password:
        update_fields['password'] = generate_password_hash(password)
    update_fields['manager_id'] = oid(g.user_id) if role == 'employee' else None

    db.users.update_one({'_id': employee_oid}, {'$set': update_fields})
    log_audit(db, g.user_id, g.username, 'edit_employee',
              target=employee_id, details={'username': username, 'role': role, 'password_changed': bool(password)})
    return jsonify({'message': f'Employee {username} updated successfully'})

@app.route('/api/employees/<employee_id>', methods=['DELETE'])
@manager_required
def api_delete_employee(employee_id):
    db = get_db()
    if db is None:
        return jsonify({'error': 'Database connection error'}), 503

    employee_oid = oid(employee_id)
    owner = db.users.find_one({'_id': employee_oid})
    if not owner:
        return jsonify({'error': 'Employee not found'}), 404

    manager_id_of_employee = owner.get('manager_id')
    if manager_id_of_employee is not None and str(manager_id_of_employee) != g.user_id:
        return jsonify({'error': 'Not authorized to delete this employee'}), 403

    db.users.delete_one({'_id': employee_oid})
    db.expenses.delete_many({'user_id': employee_oid})
    db.reports.delete_many({'user_id': employee_oid})
    log_audit(db, g.user_id, g.username, 'delete_employee',
              target=employee_id, details={'username': owner.get('username')})
    return jsonify({'message': 'Employee deleted successfully'})

@app.route('/api/convert_currency', methods=['POST'])
@token_required
def api_convert_currency():
    data = request.get_json(silent=True) or request.form
    try:
        amount = float(data.get('amount', 0))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount'}), 400

    from_currency = (data.get('from_currency') or 'USD').strip()
    to_currency = (data.get('to_currency') or 'USD').strip()
    converted_amount = convert_currency(amount, from_currency, to_currency)

    return jsonify({
        'original_amount': amount,
        'from_currency': from_currency,
        'to_currency': to_currency,
        'converted_amount': converted_amount
    })

# ------------------ RUN APP ------------------
# Initialize indexes + seed data (safe: idempotent). Runs on import so it
# also happens under a production WSGI server (gunicorn), which never
# executes the __main__ block below.
init_db()

if __name__ == '__main__':
    # try to open browser for dev convenience
    try:
        webbrowser.open("http://127.0.0.1:5050")
    except:
        pass

    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5050)), debug=True)
