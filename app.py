# =====================================================
# PhishGuard Enterprise - AI Phishing Detection Portal
# Version 2.0 - With Database, Whitelist, Blacklist,
# Statistics, and Proxy Integration
# =====================================================

from flask import Flask, request, jsonify, render_template, redirect, url_for
import re, os, sqlite3, datetime

app = Flask(__name__)

# -------------------------------------------------------
# DATABASE SETUP
# SQLite - simple file-based database, no installation needed
# -------------------------------------------------------

DB_PATH = 'phishguard.db'

def init_db():
    """Create all tables if they don't exist"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Table 1: scan history - saves every scan
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            input     TEXT NOT NULL,
            verdict   TEXT NOT NULL,
            confidence TEXT,
            explanation TEXT,
            method    TEXT,
            ip        TEXT,
            timestamp TEXT NOT NULL
        )
    ''')

    # Table 2: whitelist - trusted URLs/domains
    c.execute('''
        CREATE TABLE IF NOT EXISTS whitelist (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            url       TEXT NOT NULL UNIQUE,
            note      TEXT,
            added_by  TEXT DEFAULT 'admin',
            timestamp TEXT NOT NULL
        )
    ''')

    # Table 3: blacklist - known phishing URLs/domains
    c.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            url       TEXT NOT NULL UNIQUE,
            note      TEXT,
            added_by  TEXT DEFAULT 'admin',
            timestamp TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # allows dict-like access
    return conn

def save_scan(input_text, verdict, confidence, explanation, method, ip):
    """Save a scan result to the database"""
    conn = get_db()
    conn.execute('''
        INSERT INTO scans (input, verdict, confidence, explanation, method, ip, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (input_text[:500], verdict, confidence, explanation, method, ip,
          datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()

def check_whitelist(text):
    """Check if URL/text is in whitelist"""
    conn = get_db()
    text_lower = text.lower().strip()
    rows = conn.execute('SELECT url FROM whitelist').fetchall()
    conn.close()
    for row in rows:
        if row['url'].lower() in text_lower or text_lower in row['url'].lower():
            return True
    return False

def check_blacklist(text):
    """Check if URL/text is in blacklist"""
    conn = get_db()
    text_lower = text.lower().strip()
    rows = conn.execute('SELECT url FROM blacklist').fetchall()
    conn.close()
    for row in rows:
        if row['url'].lower() in text_lower or text_lower in row['url'].lower():
            return True, row['url']
    return False, None

def get_stats():
    """Get statistics for dashboard"""
    conn = get_db()
    total     = conn.execute('SELECT COUNT(*) as n FROM scans').fetchone()['n']
    phishing  = conn.execute("SELECT COUNT(*) as n FROM scans WHERE verdict='PHISHING'").fetchone()['n']
    suspicious= conn.execute("SELECT COUNT(*) as n FROM scans WHERE verdict='SUSPICIOUS'").fetchone()['n']
    legitimate= conn.execute("SELECT COUNT(*) as n FROM scans WHERE verdict='LEGITIMATE'").fetchone()['n']
    wl_count  = conn.execute('SELECT COUNT(*) as n FROM whitelist').fetchone()['n']
    bl_count  = conn.execute('SELECT COUNT(*) as n FROM blacklist').fetchone()['n']

    # Last 7 days chart data
    days = []
    for i in range(6, -1, -1):
        d = (datetime.datetime.now() - datetime.timedelta(days=i)).strftime('%Y-%m-%d')
        count = conn.execute(
            "SELECT COUNT(*) as n FROM scans WHERE timestamp LIKE ? AND verdict='PHISHING'",
            (d + '%',)
        ).fetchone()['n']
        days.append({'date': d[-5:], 'count': count})

    conn.close()
    return {
        'total': total, 'phishing': phishing,
        'suspicious': suspicious, 'legitimate': legitimate,
        'whitelist': wl_count, 'blacklist': bl_count,
        'chart': days
    }


# -------------------------------------------------------
# PHISHING DETECTION ENGINE
# -------------------------------------------------------

def check_phishing_rules(text):
    """Rule-based phishing detection"""
    text_lower = text.lower()
    red_flags = []

    # 1. Urgent language
    urgent_words = ["urgent", "immediately", "act now", "expire", "suspended",
                    "limited time", "click now", "verify now", "account locked",
                    "عاجل", "فوري", "انتهت", "محظور", "تحقق الان"]
    for word in urgent_words:
        if word in text_lower:
            red_flags.append("Urgent language: '" + word + "'")

    # 2. Suspicious URL patterns
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

    # 3. Sensitive info requests
    sensitive = ["password", "credit card", "ssn", "social security",
                 "bank account", "pin number", "otp", "verification code",
                 "كلمة المرور", "بطاقة الائتمان", "رقم الحساب"]
    for phrase in sensitive:
        if phrase in text_lower:
            red_flags.append("Sensitive info request: '" + phrase + "'")

    # 4. Common phishing phrases
    phrases = [
        "you have won", "congratulations you", "claim your prize",
        "your account has been", "we detected unusual", "suspicious activity",
        "confirm your identity", "update your information",
        "your account will be closed", "dear customer", "dear user",
        "لقد فزت", "تهانينا", "حسابك معلق", "تحقق من هويتك"
    ]
    for phrase in phrases:
        if phrase in text_lower:
            red_flags.append("Phishing phrase: '" + phrase + "'")

    # 5. Brand impersonation
    brands = [
        (r"paypa[l1]|p4ypal", "PayPal impersonation"),
        (r"arnazon|amaz0n", "Amazon impersonation"),
        (r"g00gle|go0gle|googie", "Google impersonation"),
        (r"micr0soft|m1crosoft", "Microsoft impersonation"),
        (r"netfl1x|netf1ix", "Netflix impersonation"),
        (r"app[l1]e|app1e", "Apple impersonation"),
    ]
    for pattern, label in brands:
        if re.search(pattern, text_lower):
            red_flags.append("Brand impersonation: " + label)

    # Safe signals
    safe_signals = []
    if "https://" in text_lower and len(red_flags) == 0:
        safe_signals.append("Uses HTTPS protocol")
    for word in ["please find attached", "regards", "sincerely", "meeting", "schedule"]:
        if word in text_lower:
            safe_signals.append("Professional language detected")
            break

    # Final decision
    if len(red_flags) >= 2:
        verdict, confidence = "PHISHING", "High"
        explanation = ("Detected " + str(len(red_flags)) + " phishing indicators: "
                      + "; ".join(red_flags[:3])
                      + ". Do NOT click links or enter personal information.")
    elif len(red_flags) == 1:
        verdict, confidence = "SUSPICIOUS", "Medium"
        explanation = ("1 warning sign found: " + red_flags[0]
                      + ". Verify the source before taking action.")
    else:
        verdict, confidence = "LEGITIMATE", "Medium"
        explanation = ("No phishing indicators found. "
                      + ("Positive: " + safe_signals[0] + ". " if safe_signals else "")
                      + "Always be cautious with unexpected messages.")

    return {
        "verdict": verdict, "confidence": confidence,
        "explanation": explanation,
        "red_flags": red_flags, "safe_signals": safe_signals
    }


# -------------------------------------------------------
# ROUTES
# -------------------------------------------------------

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    stats = get_stats()
    conn = get_db()
    recent = conn.execute(
        'SELECT * FROM scans ORDER BY id DESC LIMIT 20'
    ).fetchall()
    wl = conn.execute('SELECT * FROM whitelist ORDER BY id DESC').fetchall()
    bl = conn.execute('SELECT * FROM blacklist ORDER BY id DESC').fetchall()
    conn.close()
    return render_template('dashboard.html', stats=stats, recent=recent, wl=wl, bl=bl)

@app.route('/blocked')
def blocked():
    url = request.args.get('url', '')
    return render_template('blocked.html', url=url)

# ---- MAIN ANALYZE API ----
@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({"error": "Please provide text to analyze"}), 400

    user_input = data['text'].strip()
    if len(user_input) < 3:
        return jsonify({"error": "Input is too short"}), 400

    client_ip = request.remote_addr

    # 1. Check whitelist first
    if check_whitelist(user_input):
        result = {
            "verdict": "WHITELISTED",
            "confidence": "High",
            "explanation": "This URL/domain is in your organization's trusted whitelist.",
            "red_flags": [], "safe_signals": ["Listed in organization whitelist"],
            "method": "Whitelist Check"
        }
        save_scan(user_input, result['verdict'], result['confidence'],
                  result['explanation'], result['method'], client_ip)
        return jsonify(result)

    # 2. Check blacklist
    is_blacklisted, matched = check_blacklist(user_input)
    if is_blacklisted:
        result = {
            "verdict": "PHISHING",
            "confidence": "High",
            "explanation": "This URL is in your organization's blacklist: " + str(matched),
            "red_flags": ["Listed in organization blacklist"],
            "safe_signals": [], "method": "Blacklist Check"
        }
        save_scan(user_input, result['verdict'], result['confidence'],
                  result['explanation'], result['method'], client_ip)
        return jsonify(result)

    # 3. Try OpenAI if key available
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
                max_tokens=200
            )
            txt = response.choices[0].message.content.strip()
            verdict, confidence, explanation = "UNKNOWN", "Low", txt
            for line in txt.split('\n'):
                if line.startswith("VERDICT:"):    verdict = line.replace("VERDICT:", "").strip()
                elif line.startswith("CONFIDENCE:"): confidence = line.replace("CONFIDENCE:", "").strip()
                elif line.startswith("EXPLANATION:"): explanation = line.replace("EXPLANATION:", "").strip()
            result = {"verdict": verdict, "confidence": confidence,
                     "explanation": explanation, "red_flags": [], "safe_signals": [],
                     "method": "AI Analysis (OpenAI)"}
            save_scan(user_input, verdict, confidence, explanation, result['method'], client_ip)
            return jsonify(result)
        except Exception as e:
            print("OpenAI failed:", e)

    # 4. Rule-based fallback
    result = check_phishing_rules(user_input)
    result['method'] = 'Rule-Based Analysis'
    save_scan(user_input, result['verdict'], result['confidence'],
              result['explanation'], result['method'], client_ip)
    return jsonify(result)


# ---- PROXY CHECK API (for Squid integration) ----
@app.route('/proxy/check', methods=['GET', 'POST'])
def proxy_check():
    """
    Called by Squid proxy to check if a URL is safe
    Returns: ALLOW or BLOCK
    """
    url = request.args.get('url') or (request.get_json() or {}).get('url', '')
    if not url:
        return jsonify({"action": "ALLOW", "reason": "No URL provided"})

    # Check whitelist first
    if check_whitelist(url):
        return jsonify({"action": "ALLOW", "reason": "Whitelisted", "verdict": "WHITELISTED"})

    # Check blacklist
    is_bl, matched = check_blacklist(url)
    if is_bl:
        save_scan(url, "PHISHING", "High", "Blacklisted URL", "Proxy+Blacklist", request.remote_addr)
        return jsonify({"action": "BLOCK", "reason": "Blacklisted", "verdict": "PHISHING"})

    # Run detection
    result = check_phishing_rules(url)
    action = "BLOCK" if result['verdict'] == "PHISHING" else "ALLOW"
    save_scan(url, result['verdict'], result['confidence'],
              result['explanation'], "Proxy Check", request.remote_addr)
    return jsonify({"action": action, "verdict": result['verdict'],
                    "reason": result['explanation']})


# ---- WHITELIST / BLACKLIST MANAGEMENT ----
@app.route('/admin/whitelist/add', methods=['POST'])
def add_whitelist():
    data = request.get_json()
    url = (data or {}).get('url', '').strip()
    note = (data or {}).get('note', '')
    if not url:
        return jsonify({"error": "URL required"}), 400
    try:
        conn = get_db()
        conn.execute('INSERT INTO whitelist (url, note, timestamp) VALUES (?, ?, ?)',
                     (url, note, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": url + " added to whitelist"})
    except Exception as e:
        return jsonify({"error": "Already exists or error: " + str(e)}), 400

@app.route('/admin/blacklist/add', methods=['POST'])
def add_blacklist():
    data = request.get_json()
    url = (data or {}).get('url', '').strip()
    note = (data or {}).get('note', '')
    if not url:
        return jsonify({"error": "URL required"}), 400
    try:
        conn = get_db()
        conn.execute('INSERT INTO blacklist (url, note, timestamp) VALUES (?, ?, ?)',
                     (url, note, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": url + " added to blacklist"})
    except Exception as e:
        return jsonify({"error": "Already exists or error: " + str(e)}), 400

@app.route('/admin/whitelist/delete/<int:id>', methods=['DELETE'])
def del_whitelist(id):
    conn = get_db()
    conn.execute('DELETE FROM whitelist WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/admin/blacklist/delete/<int:id>', methods=['DELETE'])
def del_blacklist(id):
    conn = get_db()
    conn.execute('DELETE FROM blacklist WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/api/stats')
def api_stats():
    return jsonify(get_stats())

@app.route('/api/scans')
def api_scans():
    conn = get_db()
    scans = conn.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 50').fetchall()
    conn.close()
    return jsonify([dict(s) for s in scans])


# -------------------------------------------------------
# INIT & RUN
# -------------------------------------------------------

init_db()

if __name__ == '__main__':
    print("PhishGuard Enterprise starting...")
    print("Portal:    http://localhost:5000")
    print("Dashboard: http://localhost:5000/dashboard")
    app.run(debug=True, port=5000) 
