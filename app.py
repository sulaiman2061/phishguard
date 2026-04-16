# =====================================================
# PhishGuard Enterprise v3.0
# Full system: Auth + Roles + User Management + Reports
# =====================================================

from flask import Flask, request, jsonify, render_template, redirect, session
from functools import wraps
import re, os, sqlite3, datetime, hashlib, secrets

app = Flask(__name__)
app.secret_key = 'phishguard-super-secret-2025'

DB_PATH = 'phishguard.db'

# -------------------------------------------------------
# HELPERS
# -------------------------------------------------------

def hash_pass(password):
    return hashlib.sha256(password.encode()).hexdigest()

def now():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# -------------------------------------------------------
# DATABASE SETUP
# -------------------------------------------------------

def init_db():
    conn = get_db()
    c = conn.cursor()

    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        username   TEXT NOT NULL UNIQUE,
        password   TEXT NOT NULL,
        role       TEXT DEFAULT 'user',
        created_at TEXT NOT NULL
    )''')

    # Scans table with user_id
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER DEFAULT 0,
        username    TEXT DEFAULT 'guest',
        input       TEXT NOT NULL,
        verdict     TEXT NOT NULL,
        confidence  TEXT,
        explanation TEXT,
        method      TEXT,
        ip          TEXT,
        timestamp   TEXT NOT NULL
    )''')

    # Whitelist
    c.execute('''CREATE TABLE IF NOT EXISTS whitelist (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        url       TEXT NOT NULL UNIQUE,
        note      TEXT,
        timestamp TEXT NOT NULL
    )''')

    # Blacklist
    c.execute('''CREATE TABLE IF NOT EXISTS blacklist (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        url       TEXT NOT NULL UNIQUE,
        note      TEXT,
        timestamp TEXT NOT NULL
    )''')

    # Create default admin if not exists
    try:
        conn.execute(
            'INSERT INTO users (username, password, role, created_at) VALUES (?,?,?,?)',
            ('admin', hash_pass('Admin@1234'), 'admin', now())
        )
        conn.commit()
        print("Default admin created: admin / Admin@1234")
    except:
        pass

    conn.close()

# -------------------------------------------------------
# AUTH DECORATORS
# -------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect('/login')
        if session.get('role') != 'admin':
            return render_template('denied.html'), 403
        return f(*args, **kwargs)
    return decorated

# -------------------------------------------------------
# DETECTION ENGINE
# -------------------------------------------------------

def check_phishing_rules(text):
    text_lower = text.lower()
    red_flags = []

    urgent_words = ["urgent", "immediately", "act now", "expire", "suspended",
                    "limited time", "click now", "verify now", "account locked",
                    "عاجل", "فوري", "انتهت", "محظور", "تحقق الان"]
    for word in urgent_words:
        if word in text_lower:
            red_flags.append("Urgent language: '" + word + "'")

    url_patterns = [
        r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"bit\.ly|tinyurl|t\.co|goo\.gl",
        r"login.*\.(xyz|tk|ml|ga|cf|gq)",
        r"secure.*paypal|paypal.*secure",
        r"amazon.*verify|verify.*amazon",
        r"@.*http",
    ]
    for pattern in url_patterns:
        if re.search(pattern, text_lower):
            red_flags.append("Suspicious URL pattern found")
            break

    sensitive = ["password", "credit card", "ssn", "social security",
                 "bank account", "pin number", "otp", "verification code",
                 "كلمة المرور", "بطاقة الائتمان", "رقم الحساب"]
    for phrase in sensitive:
        if phrase in text_lower:
            red_flags.append("Sensitive info request: '" + phrase + "'")

    phrases = ["you have won", "congratulations you", "claim your prize",
               "your account has been", "we detected unusual", "suspicious activity",
               "confirm your identity", "update your information",
               "your account will be closed", "dear customer", "dear user",
               "لقد فزت", "تهانينا", "حسابك معلق"]
    for phrase in phrases:
        if phrase in text_lower:
            red_flags.append("Phishing phrase: '" + phrase + "'")

    brands = [
        (r"paypa[l1]|p4ypal", "PayPal impersonation"),
        (r"arnazon|amaz0n", "Amazon impersonation"),
        (r"g00gle|go0gle", "Google impersonation"),
        (r"micr0soft|m1crosoft", "Microsoft impersonation"),
        (r"netfl1x|netf1ix", "Netflix impersonation"),
        (r"app[l1]e-id|app1e", "Apple impersonation"),
    ]
    for pattern, label in brands:
        if re.search(pattern, text_lower):
            red_flags.append("Brand impersonation: " + label)

    safe_signals = []
    if "https://" in text_lower and len(red_flags) == 0:
        safe_signals.append("Uses HTTPS protocol")
    for word in ["please find attached", "regards", "sincerely", "meeting", "schedule"]:
        if word in text_lower:
            safe_signals.append("Professional language detected")
            break

    if len(red_flags) >= 2:
        verdict, confidence = "PHISHING", "High"
        explanation = ("Detected " + str(len(red_flags)) + " phishing indicators: "
                      + "; ".join(red_flags[:3])
                      + ". Do NOT click links or enter personal information.")
    elif len(red_flags) == 1:
        verdict, confidence = "SUSPICIOUS", "Medium"
        explanation = "1 warning sign: " + red_flags[0] + ". Verify the source first."
    else:
        verdict, confidence = "LEGITIMATE", "Medium"
        explanation = ("No phishing indicators found. "
                      + ("Positive: " + safe_signals[0] + ". " if safe_signals else "")
                      + "Always be cautious with unexpected messages.")

    return {"verdict": verdict, "confidence": confidence,
            "explanation": explanation,
            "red_flags": red_flags, "safe_signals": safe_signals}

def check_whitelist(text):
    conn = get_db()
    rows = conn.execute('SELECT url FROM whitelist').fetchall()
    conn.close()
    for row in rows:
        if row['url'].lower() in text.lower():
            return True
    return False

def check_blacklist(text):
    conn = get_db()
    rows = conn.execute('SELECT url FROM blacklist').fetchall()
    conn.close()
    for row in rows:
        if row['url'].lower() in text.lower():
            return True, row['url']
    return False, None

def save_scan(user_id, username, input_text, verdict, confidence, explanation, method, ip):
    conn = get_db()
    conn.execute('''INSERT INTO scans
        (user_id, username, input, verdict, confidence, explanation, method, ip, timestamp)
        VALUES (?,?,?,?,?,?,?,?,?)''',
        (user_id, username, input_text[:500], verdict, confidence,
         explanation, method, ip, now()))
    conn.commit()
    conn.close()

# -------------------------------------------------------
# STATS HELPERS
# -------------------------------------------------------

def get_admin_stats():
    conn = get_db()
    total      = conn.execute('SELECT COUNT(*) as n FROM scans').fetchone()['n']
    phishing   = conn.execute("SELECT COUNT(*) as n FROM scans WHERE verdict='PHISHING'").fetchone()['n']
    suspicious = conn.execute("SELECT COUNT(*) as n FROM scans WHERE verdict='SUSPICIOUS'").fetchone()['n']
    legitimate = conn.execute("SELECT COUNT(*) as n FROM scans WHERE verdict='LEGITIMATE'").fetchone()['n']
    users      = conn.execute("SELECT COUNT(*) as n FROM users WHERE role='user'").fetchone()['n']
    wl         = conn.execute('SELECT COUNT(*) as n FROM whitelist').fetchone()['n']
    bl         = conn.execute('SELECT COUNT(*) as n FROM blacklist').fetchone()['n']
    days = []
    for i in range(6, -1, -1):
        d = (datetime.datetime.now() - datetime.timedelta(days=i)).strftime('%Y-%m-%d')
        count = conn.execute(
            "SELECT COUNT(*) as n FROM scans WHERE timestamp LIKE ? AND verdict='PHISHING'",
            (d + '%',)).fetchone()['n']
        days.append({'date': d[-5:], 'count': count})
    conn.close()
    return {'total': total, 'phishing': phishing, 'suspicious': suspicious,
            'legitimate': legitimate, 'users': users, 'whitelist': wl,
            'blacklist': bl, 'chart': days}

def get_user_stats(user_id):
    conn = get_db()
    total      = conn.execute('SELECT COUNT(*) as n FROM scans WHERE user_id=?', (user_id,)).fetchone()['n']
    phishing   = conn.execute("SELECT COUNT(*) as n FROM scans WHERE user_id=? AND verdict='PHISHING'", (user_id,)).fetchone()['n']
    suspicious = conn.execute("SELECT COUNT(*) as n FROM scans WHERE user_id=? AND verdict='SUSPICIOUS'", (user_id,)).fetchone()['n']
    legitimate = conn.execute("SELECT COUNT(*) as n FROM scans WHERE user_id=? AND verdict='LEGITIMATE'", (user_id,)).fetchone()['n']
    days = []
    for i in range(6, -1, -1):
        d = (datetime.datetime.now() - datetime.timedelta(days=i)).strftime('%Y-%m-%d')
        count = conn.execute(
            "SELECT COUNT(*) as n FROM scans WHERE user_id=? AND timestamp LIKE ? AND verdict='PHISHING'",
            (user_id, d + '%',)).fetchone()['n']
        days.append({'date': d[-5:], 'count': count})
    conn.close()
    return {'total': total, 'phishing': phishing,
            'suspicious': suspicious, 'legitimate': legitimate, 'chart': days}

# -------------------------------------------------------
# ROUTES — PUBLIC
# -------------------------------------------------------

@app.route('/')
def home():
    user = {'username': session.get('username', ''), 'role': session.get('role', '')}
    return render_template('index.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect('/')
    if request.method == 'POST':
        data = request.get_json() or {}
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        conn = get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE username=? AND password=?',
            (username, hash_pass(password))
        ).fetchone()
        conn.close()
        if user:
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['role']     = user['role']
            return jsonify({'success': True, 'role': user['role']})
        return jsonify({'error': 'Wrong username or password'}), 401
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# -------------------------------------------------------
# ROUTES — USER (logged in)
# -------------------------------------------------------

@app.route('/profile')
@login_required
def profile():
    stats = get_user_stats(session['user_id'])
    conn = get_db()
    scans = conn.execute(
        'SELECT * FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 30',
        (session['user_id'],)
    ).fetchall()
    conn.close()
    return render_template('profile.html',
                           user=session, stats=stats, scans=scans)

# -------------------------------------------------------
# ROUTES — ADMIN ONLY
# -------------------------------------------------------

@app.route('/dashboard')
@admin_required
def dashboard():
    stats = get_admin_stats()
    conn = get_db()
    recent = conn.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 30').fetchall()
    users  = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    wl     = conn.execute('SELECT * FROM whitelist ORDER BY id DESC').fetchall()
    bl     = conn.execute('SELECT * FROM blacklist ORDER BY id DESC').fetchall()
    conn.close()
    return render_template('dashboard.html',
                           stats=stats, recent=recent,
                           users=users, wl=wl, bl=bl)

@app.route('/admin/report')
@admin_required
def admin_report():
    stats = get_admin_stats()
    conn = get_db()
    # Top phishing users
    top_users = conn.execute('''
        SELECT username, COUNT(*) as total,
               SUM(CASE WHEN verdict='PHISHING' THEN 1 ELSE 0 END) as phishing
        FROM scans GROUP BY username ORDER BY total DESC LIMIT 10
    ''').fetchall()
    # Recent phishing
    recent_phishing = conn.execute(
        "SELECT * FROM scans WHERE verdict='PHISHING' ORDER BY id DESC LIMIT 20"
    ).fetchall()
    all_users = conn.execute('SELECT * FROM users ORDER BY id').fetchall()
    conn.close()
    report_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    return render_template('report.html', stats=stats, top_users=top_users,
                           recent_phishing=recent_phishing,
                           all_users=all_users, report_date=report_date)

# -------------------------------------------------------
# API — ANALYZE
# -------------------------------------------------------

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({"error": "Please provide text"}), 400
    user_input = data['text'].strip()
    if len(user_input) < 3:
        return jsonify({"error": "Input too short"}), 400

    user_id  = session.get('user_id', 0)
    username = session.get('username', 'guest')
    ip       = request.remote_addr

    # 1. Whitelist
    if check_whitelist(user_input):
        result = {"verdict": "WHITELISTED", "confidence": "High",
                  "explanation": "This domain is in your organization's trusted whitelist.",
                  "red_flags": [], "safe_signals": ["Listed in whitelist"],
                  "method": "Whitelist Check"}
        save_scan(user_id, username, user_input, result['verdict'],
                  result['confidence'], result['explanation'], result['method'], ip)
        return jsonify(result)

    # 2. Blacklist
    is_bl, matched = check_blacklist(user_input)
    if is_bl:
        result = {"verdict": "PHISHING", "confidence": "High",
                  "explanation": "This URL is in the organization blacklist: " + str(matched),
                  "red_flags": ["Listed in blacklist"], "safe_signals": [],
                  "method": "Blacklist Check"}
        save_scan(user_id, username, user_input, result['verdict'],
                  result['confidence'], result['explanation'], result['method'], ip)
        return jsonify(result)

    # 3. OpenAI (optional)
    api_key = os.environ.get('OPENAI_API_KEY')
    if api_key:
        try:
            import openai
            openai.api_key = api_key
            prompt = ("Is this phishing or legitimate?\n" + user_input +
                     "\nVERDICT: [PHISHING or LEGITIMATE]\nCONFIDENCE: [High/Medium/Low]\nEXPLANATION: [one sentence]")
            response = openai.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=200)
            txt = response.choices[0].message.content.strip()
            verdict, confidence, explanation = "UNKNOWN", "Low", txt
            for line in txt.split('\n'):
                if line.startswith("VERDICT:"): verdict = line.replace("VERDICT:", "").strip()
                elif line.startswith("CONFIDENCE:"): confidence = line.replace("CONFIDENCE:", "").strip()
                elif line.startswith("EXPLANATION:"): explanation = line.replace("EXPLANATION:", "").strip()
            result = {"verdict": verdict, "confidence": confidence,
                     "explanation": explanation, "red_flags": [], "safe_signals": [],
                     "method": "AI Analysis (OpenAI)"}
            save_scan(user_id, username, user_input, verdict, confidence,
                     explanation, result['method'], ip)
            return jsonify(result)
        except Exception as e:
            print("OpenAI failed:", e)

    # 4. Rule-based
    result = check_phishing_rules(user_input)
    result['method'] = 'Rule-Based Analysis'
    save_scan(user_id, username, user_input, result['verdict'],
              result['confidence'], result['explanation'], result['method'], ip)
    return jsonify(result)

# -------------------------------------------------------
# API — PROXY
# -------------------------------------------------------

@app.route('/proxy/check', methods=['GET', 'POST'])
def proxy_check():
    url = request.args.get('url') or (request.get_json() or {}).get('url', '')
    if not url:
        return jsonify({"action": "ALLOW"})
    if check_whitelist(url):
        return jsonify({"action": "ALLOW", "verdict": "WHITELISTED"})
    is_bl, matched = check_blacklist(url)
    if is_bl:
        save_scan(0, 'proxy', url, "PHISHING", "High", "Blacklisted", "Proxy", request.remote_addr)
        return jsonify({"action": "BLOCK", "verdict": "PHISHING"})
    result = check_phishing_rules(url)
    action = "BLOCK" if result['verdict'] == "PHISHING" else "ALLOW"
    save_scan(0, 'proxy', url, result['verdict'], result['confidence'],
              result['explanation'], "Proxy Check", request.remote_addr)
    return jsonify({"action": action, "verdict": result['verdict']})

@app.route('/blocked')
def blocked():
    return render_template('blocked.html', url=request.args.get('url', ''))

# -------------------------------------------------------
# API — ADMIN USER MANAGEMENT
# -------------------------------------------------------

@app.route('/admin/users/add', methods=['POST'])
@admin_required
def add_user():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    role     = data.get('role', 'user')
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if role not in ['user', 'admin']:
        role = 'user'
    try:
        conn = get_db()
        conn.execute('INSERT INTO users (username, password, role, created_at) VALUES (?,?,?,?)',
                     (username, hash_pass(password), role, now()))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": username + " added successfully"})
    except:
        return jsonify({"error": "Username already exists"}), 400

@app.route('/admin/users/delete/<int:uid>', methods=['DELETE'])
@admin_required
def delete_user(uid):
    if uid == session.get('user_id'):
        return jsonify({"error": "Cannot delete yourself"}), 400
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id=?', (uid,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

# -------------------------------------------------------
# API — WHITELIST / BLACKLIST
# -------------------------------------------------------

@app.route('/admin/whitelist/add', methods=['POST'])
@admin_required
def add_whitelist():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    try:
        conn = get_db()
        conn.execute('INSERT INTO whitelist (url, note, timestamp) VALUES (?,?,?)',
                     (url, data.get('note', ''), now()))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except:
        return jsonify({"error": "Already exists"}), 400

@app.route('/admin/blacklist/add', methods=['POST'])
@admin_required
def add_blacklist():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    try:
        conn = get_db()
        conn.execute('INSERT INTO blacklist (url, note, timestamp) VALUES (?,?,?)',
                     (url, data.get('note', ''), now()))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except:
        return jsonify({"error": "Already exists"}), 400

@app.route('/admin/whitelist/delete/<int:id>', methods=['DELETE'])
@admin_required
def del_whitelist(id):
    conn = get_db()
    conn.execute('DELETE FROM whitelist WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/admin/blacklist/delete/<int:id>', methods=['DELETE'])
@admin_required
def del_blacklist(id):
    conn = get_db()
    conn.execute('DELETE FROM blacklist WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

# -------------------------------------------------------
# API — STATS
# -------------------------------------------------------

@app.route('/api/stats')
def api_stats():
    if session.get('role') == 'admin':
        return jsonify(get_admin_stats())
    elif session.get('user_id'):
        return jsonify(get_user_stats(session['user_id']))
    # Guest — basic only
    conn = get_db()
    total = conn.execute('SELECT COUNT(*) as n FROM scans WHERE user_id=0').fetchone()['n']
    conn.close()
    return jsonify({'total': total})

@app.route('/api/scans')
@login_required
def api_scans():
    conn = get_db()
    if session.get('role') == 'admin':
        scans = conn.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 50').fetchall()
    else:
        scans = conn.execute(
            'SELECT * FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 50',
            (session['user_id'],)).fetchall()
    conn.close()
    return jsonify([dict(s) for s in scans])

# -------------------------------------------------------
# INIT & RUN
# -------------------------------------------------------

init_db()

if __name__ == '__main__':
    print("\n" + "="*50)
    print("  PhishGuard Enterprise v3.0")
    print("="*50)
    print("  Portal:    http://localhost:5000")
    print("  Login:     http://localhost:5000/login")
    print("  Dashboard: http://localhost:5000/dashboard")
    print("  Report:    http://localhost:5000/admin/report")
    print("  Admin:     admin / Admin@1234")
    print("="*50 + "\n")
    app.run(debug=True, port=5000)
