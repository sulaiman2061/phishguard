# =====================================================
# AIPDA - AI Powered Detection of Phishing Attacks
# Version 4.0 - Enterprise Edition
# =====================================================

from flask import Flask, request, jsonify, render_template, redirect, session
try:
    from nca_engine import analyze_with_nca, is_nca_official, get_nca_stats
    NCA_ENABLED = True
except:
    NCA_ENABLED = False
    def analyze_with_nca(t): return {'nca_result':'UNKNOWN','verdict':None,'nca_flags':[],'method':None}
    def is_nca_official(t): return False, None
    def get_nca_stats(): return {}
from functools import wraps
import re, os, sqlite3, datetime, hashlib, urllib.parse

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'aipda-enterprise-2025')
DB_PATH = 'aipda.db'

# -------------------------------------------------------
# TRUSTED DOMAINS
# -------------------------------------------------------
TRUSTED_DOMAINS = {
    'google.com','google.com.sa','googleapis.com','gstatic.com',
    'microsoft.com','microsoftonline.com','office.com','office365.com',
    'outlook.com','live.com','hotmail.com','bing.com',
    'apple.com','icloud.com','itunes.com',
    'amazon.com','amazon.sa','amazon.co.uk','amazon.de',
    'ebay.com','alibaba.com','aliexpress.com',
    'facebook.com','fb.com','instagram.com','twitter.com',
    'x.com','linkedin.com','youtube.com','tiktok.com',
    'paypal.com','stripe.com','visa.com','mastercard.com',
    'github.com','gitlab.com','stackoverflow.com',
    'cloudflare.com','digitalocean.com','render.com','onrender.com',
    'stc.com.sa','mobily.com.sa','zain.com.sa',
    'alrajhibank.com.sa','sab.com','riyadbank.com',
    'absher.sa','vat.gov.sa','zatca.gov.sa','moi.gov.sa',
    'vision2030.gov.sa','nca.gov.sa','spa.gov.sa',
    'arabeast.edu.sa','ksu.edu.sa','kau.edu.sa','kfupm.edu.sa',
    'redhat.com','access.redhat.com','console.redhat.com',
    'cloud.redhat.com','registry.redhat.io','sso.redhat.com',
    'ubuntu.com','debian.org','centos.org','fedoraproject.org',
    'netflix.com','spotify.com','adobe.com','zoom.us',
    'dropbox.com','slack.com','notion.so','wikipedia.org',
    'python.org','flask.palletsprojects.com',
}

def extract_domain(text):
    try:
        text = text.strip().lower()
        if text.startswith('http'):
            parsed = urllib.parse.urlparse(text)
            domain = parsed.netloc
        else:
            match = re.search(r'https?://([^/\s?#]+)', text)
            domain = match.group(1) if match else text
        domain = re.sub(r'^www\.', '', domain).split(':')[0]
        return domain.lower()
    except:
        return ''

def is_trusted_domain(text):
    domain = extract_domain(text)
    if not domain:
        return False
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith('.' + trusted):
            return True
    return False

# -------------------------------------------------------
# HELPERS & DB
# -------------------------------------------------------
def hash_pass(p): return hashlib.sha256(p.encode()).hexdigest()
def now(): return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER DEFAULT 0,
        username TEXT DEFAULT 'guest',
        input TEXT NOT NULL,
        verdict TEXT NOT NULL,
        confidence TEXT,
        explanation TEXT,
        method TEXT,
        ip TEXT,
        timestamp TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL UNIQUE,
        note TEXT,
        timestamp TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL UNIQUE,
        note TEXT,
        timestamp TEXT NOT NULL)''')
    try:
        conn.execute('INSERT INTO users (username,password,role,created_at) VALUES (?,?,?,?)',
                     ('admin', hash_pass('Admin@1234'), 'admin', now()))
        conn.commit()
        print("  Default admin: admin / Admin@1234")
    except: pass
    conn.close()

def save_scan(user_id, username, inp, verdict, confidence, explanation, method, ip):
    conn = get_db()
    conn.execute('''INSERT INTO scans (user_id,username,input,verdict,confidence,explanation,method,ip,timestamp)
        VALUES (?,?,?,?,?,?,?,?,?)''',
        (user_id, username, inp[:500], verdict, confidence, explanation, method, ip, now()))
    conn.commit()
    conn.close()

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

# -------------------------------------------------------
# DETECTION ENGINE v4.0
# -------------------------------------------------------
def check_phishing_rules(text):
    text_lower = text.lower().strip()
    red_flags = []
    safe_signals = []
    domain = extract_domain(text)

    # Check trusted domain first
    if domain and is_trusted_domain(text):
        if len(text_lower) < 200 and 'urgent' not in text_lower and 'password' not in text_lower:
            return {
                "verdict": "LEGITIMATE", "confidence": "High",
                "explanation": "Verified trusted domain (" + domain + "). No phishing indicators.",
                "red_flags": [], "safe_signals": ["Verified trusted domain: " + domain]
            }

    # 1. Urgent language
    for word in ["urgent","immediately","act now","expire","suspended","limited time",
                 "click now","verify now","account locked","final notice","response required",
                 "عاجل","فوري","انتهت","محظور","تحقق الان","تنبيه عاجل"]:
        if word in text_lower:
            red_flags.append("Urgent language: '" + word + "'")
            break

    # 2. IP address URL
    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text_lower):
        red_flags.append("Direct IP address URL — no legitimate site uses raw IP")

    # 3. URL shorteners
    if re.search(r'\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly)\b', text_lower):
        red_flags.append("URL shortener — destination unknown")

    # 4. Brand impersonation (only if not trusted)
    if not is_trusted_domain(text):
        for pattern, label in [
            (r'paypa[l1]\.(?!com)|p4ypal|paypa1', "Fake PayPal"),
            (r'amaz[o0]n\.(?!com|sa|co)|arnazon|amaz0n', "Fake Amazon"),
            (r'g[o0]{2}gle\.(?!com)|go0gle|g00gle', "Fake Google"),
            (r'micr[o0]s[o0]ft\.(?!com)|m1crosoft', "Fake Microsoft"),
            (r'netfl[i1]x\.(?!com)|netf1ix', "Fake Netflix"),
            (r'app[l1]e-(?:id|support)|app1e\.', "Fake Apple"),
            (r'faceb[o0]{2}k\.(?!com)|faceb00k', "Fake Facebook"),
        ]:
            if re.search(pattern, text_lower):
                red_flags.append("Brand impersonation: " + label)

    # 5. Sensitive info requests
    for phrase in ["enter your password","credit card","social security","ssn",
                   "bank account number","pin number","enter your otp",
                   "كلمة المرور","رقم البطاقة","رقم الحساب","الرقم السري"]:
        if phrase in text_lower:
            red_flags.append("Requests sensitive info: '" + phrase + "'")
            break

    # 6. Phishing phrases
    for phrase in ["you have won","claim your prize","account has been compromised",
                   "confirm your identity","your account will be closed",
                   "dear valued customer","dear account holder",
                   "لقد فزت","تم اختراق حسابك","حسابك سيتم إغلاقه","عزيزي العميل"]:
        if phrase in text_lower:
            red_flags.append("Phishing phrase: '" + phrase + "'")
            break

    # 7. Suspicious TLD
    if re.search(r'https?://[^\s/]+\.(xyz|tk|ml|ga|cf|gq|pw|top|click|loan|zip)\b', text_lower):
        red_flags.append("High-risk domain extension")

    # 8. @ in URL
    if re.search(r'https?://[^\s]*@', text_lower):
        red_flags.append("URL contains @ — common phishing trick")

    # Safe signals
    if 'https://' in text_lower and not red_flags:
        safe_signals.append("Uses HTTPS encryption")
    for w in ["regards","sincerely","please find attached","meeting","schedule"]:
        if w in text_lower and not red_flags:
            safe_signals.append("Professional language")
            break

    # Decision
    score = len(red_flags)
    if score >= 3:
        verdict, confidence = "PHISHING", "High"
        explanation = "HIGH RISK: " + str(score) + " indicators — " + "; ".join(red_flags[:2]) + ". Do NOT click links."
    elif score == 2:
        verdict, confidence = "PHISHING", "Medium"
        explanation = "Likely phishing: " + "; ".join(red_flags) + ". Verify before acting."
    elif score == 1:
        verdict, confidence = "SUSPICIOUS", "Medium"
        explanation = "One warning: " + red_flags[0] + ". Proceed with caution."
    else:
        verdict, confidence = "LEGITIMATE", "Medium"
        explanation = ("No phishing indicators. "
                      + ("Positive: " + safe_signals[0] + ". " if safe_signals else "")
                      + "Stay cautious with unexpected messages.")

    return {"verdict": verdict, "confidence": confidence, "explanation": explanation,
            "red_flags": red_flags, "safe_signals": safe_signals}

# -------------------------------------------------------
# STATS
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
    for i in range(6,-1,-1):
        d = (datetime.datetime.now()-datetime.timedelta(days=i)).strftime('%Y-%m-%d')
        count = conn.execute("SELECT COUNT(*) as n FROM scans WHERE timestamp LIKE ? AND verdict='PHISHING'",(d+'%',)).fetchone()['n']
        days.append({'date':d[-5:],'count':count})
    conn.close()
    return {'total':total,'phishing':phishing,'suspicious':suspicious,'legitimate':legitimate,
            'users':users,'whitelist':wl,'blacklist':bl,'chart':days}

def get_user_stats(user_id):
    conn = get_db()
    total      = conn.execute('SELECT COUNT(*) as n FROM scans WHERE user_id=?',(user_id,)).fetchone()['n']
    phishing   = conn.execute("SELECT COUNT(*) as n FROM scans WHERE user_id=? AND verdict='PHISHING'",(user_id,)).fetchone()['n']
    suspicious = conn.execute("SELECT COUNT(*) as n FROM scans WHERE user_id=? AND verdict='SUSPICIOUS'",(user_id,)).fetchone()['n']
    legitimate = conn.execute("SELECT COUNT(*) as n FROM scans WHERE user_id=? AND verdict='LEGITIMATE'",(user_id,)).fetchone()['n']
    days = []
    for i in range(6,-1,-1):
        d = (datetime.datetime.now()-datetime.timedelta(days=i)).strftime('%Y-%m-%d')
        count = conn.execute("SELECT COUNT(*) as n FROM scans WHERE user_id=? AND timestamp LIKE ? AND verdict='PHISHING'",(user_id,d+'%')).fetchone()['n']
        days.append({'date':d[-5:],'count':count})
    conn.close()
    return {'total':total,'phishing':phishing,'suspicious':suspicious,'legitimate':legitimate,'chart':days}

# -------------------------------------------------------
# AUTH
# -------------------------------------------------------
def login_required(f):
    @wraps(f)
    def dec(*a,**k):
        if not session.get('user_id'): return redirect('/login')
        return f(*a,**k)
    return dec

def admin_required(f):
    @wraps(f)
    def dec(*a,**k):
        if not session.get('user_id'): return redirect('/login')
        if session.get('role') != 'admin': return render_template('denied.html'),403
        return f(*a,**k)
    return dec

# -------------------------------------------------------
# ROUTES
# -------------------------------------------------------
@app.route('/')
def home():
    return render_template('index.html', user={'username':session.get('username',''),'role':session.get('role','')})

@app.route('/login', methods=['GET','POST'])
def login():
    if session.get('user_id'):
        return redirect('/dashboard' if session.get('role')=='admin' else '/profile')
    if request.method == 'POST':
        data = request.get_json() or {}
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username=? AND password=?',
                            (data.get('username','').strip(), hash_pass(data.get('password','').strip()))).fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return jsonify({'success':True,'role':user['role']})
        return jsonify({'error':'Wrong username or password'}),401
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/profile')
@login_required
def profile():
    stats = get_user_stats(session['user_id'])
    conn = get_db()
    scans = conn.execute('SELECT * FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 30',(session['user_id'],)).fetchall()
    conn.close()
    return render_template('profile.html', user=session, stats=stats, scans=scans)

@app.route('/dashboard')
@admin_required
def dashboard():
    stats = get_admin_stats()
    conn = get_db()
    recent = conn.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 30').fetchall()
    users  = conn.execute('SELECT * FROM users ORDER BY id DESC').fetchall()
    wl     = conn.execute('SELECT * FROM whitelist ORDER BY id DESC').fetchall()
    bl     = conn.execute('SELECT * FROM blacklist ORDER BY id DESC').fetchall()
    conn.close()
    return render_template('dashboard.html', stats=stats, recent=recent,
                           users=users, wl=wl, bl=bl, admin_username=session.get('username'))

@app.route('/admin/report')
@admin_required
def admin_report():
    stats = get_admin_stats()
    conn = get_db()
    top_users = conn.execute('''SELECT username, COUNT(*) as total,
               SUM(CASE WHEN verdict='PHISHING' THEN 1 ELSE 0 END) as phishing
        FROM scans GROUP BY username ORDER BY total DESC LIMIT 10''').fetchall()
    recent_phishing = conn.execute("SELECT * FROM scans WHERE verdict='PHISHING' ORDER BY id DESC LIMIT 20").fetchall()
    all_users = conn.execute('SELECT * FROM users ORDER BY id').fetchall()
    conn.close()
    return render_template('report.html', stats=stats, top_users=top_users,
                           recent_phishing=recent_phishing, all_users=all_users,
                           report_date=datetime.datetime.now().strftime('%Y-%m-%d %H:%M'))

@app.route('/blocked')
def blocked():
    return render_template('blocked.html', url=request.args.get('url',''))

# -------------------------------------------------------
# ANALYZE API
# -------------------------------------------------------
@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({"error":"Please provide text"}),400
    user_input = data['text'].strip()
    if len(user_input) < 3:
        return jsonify({"error":"Input too short"}),400
    user_id  = session.get('user_id', 0)
    username = session.get('username', 'guest')
    ip = request.remote_addr

    # ── NCA CHECK (GROUND TRUTH — runs before everything) ──
    # لا يمكن تجاوزها حتى لو الدومين في الـ Whitelist
    if NCA_ENABLED:
        nca = analyze_with_nca(user_input)

        # NCA رسمي — موثوق تماماً
        if nca['nca_result'] == 'OFFICIAL':
            result = {
                'verdict': 'LEGITIMATE',
                'confidence': 'High',
                'explanation': nca['explanation'],
                'red_flags': [],
                'safe_signals': ['NCA Verified Official Domain'],
                'method': 'NCA Official Database'
            }
            save_scan(user_id,username,user_input,result['verdict'],
                      result['confidence'],result['explanation'],result['method'],ip)
            return jsonify(result)

        # NCA تصيد — محجوب حتى لو في الـ Whitelist
        if nca['nca_result'] == 'PHISHING':
            result = {
                'verdict': 'PHISHING',
                'confidence': nca.get('confidence','High'),
                'explanation': nca['explanation'],
                'red_flags': nca.get('nca_flags',[]),
                'safe_signals': [],
                'method': nca.get('method','NCA Threat Intelligence')
            }
            save_scan(user_id,username,user_input,result['verdict'],
                      result['confidence'],result['explanation'],result['method'],ip)
            return jsonify(result)

    # ── WHITELIST CHECK ──
    if check_whitelist(user_input):
        result = {"verdict":"WHITELISTED","confidence":"High",
                  "explanation":"This domain is in your organization's trusted whitelist.",
                  "red_flags":[],"safe_signals":["Organization whitelist"],"method":"Whitelist Check"}
        save_scan(user_id,username,user_input,result['verdict'],result['confidence'],result['explanation'],result['method'],ip)
        return jsonify(result)

    is_bl, matched = check_blacklist(user_input)
    if is_bl:
        result = {"verdict":"PHISHING","confidence":"High",
                  "explanation":"Blacklisted URL: "+str(matched),
                  "red_flags":["Blacklist match"],"safe_signals":[],"method":"Blacklist Check"}
        save_scan(user_id,username,user_input,result['verdict'],result['confidence'],result['explanation'],result['method'],ip)
        return jsonify(result)

    api_key = os.environ.get('OPENAI_API_KEY')
    if api_key:
        try:
            import openai
            openai.api_key = api_key
            response = openai.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role":"user","content":"Is this phishing?\n"+user_input+"\nVERDICT: [PHISHING or LEGITIMATE]\nCONFIDENCE: [High/Medium/Low]\nEXPLANATION: [one sentence]"}],
                max_tokens=200)
            txt = response.choices[0].message.content.strip()
            verdict,confidence,explanation = "UNKNOWN","Low",txt
            for line in txt.split('\n'):
                if line.startswith("VERDICT:"): verdict=line.replace("VERDICT:","").strip()
                elif line.startswith("CONFIDENCE:"): confidence=line.replace("CONFIDENCE:","").strip()
                elif line.startswith("EXPLANATION:"): explanation=line.replace("EXPLANATION:","").strip()
            result = {"verdict":verdict,"confidence":confidence,"explanation":explanation,
                      "red_flags":[],"safe_signals":[],"method":"AI Analysis (OpenAI)"}
            save_scan(user_id,username,user_input,verdict,confidence,explanation,result['method'],ip)
            return jsonify(result)
        except Exception as e:
            print("OpenAI failed:",e)

    result = check_phishing_rules(user_input)
    result['method'] = 'Rule-Based v4.0'
    save_scan(user_id,username,user_input,result['verdict'],result['confidence'],result['explanation'],result['method'],ip)
    return jsonify(result)

@app.route('/proxy/check', methods=['GET','POST'])
def proxy_check():
    url = request.args.get('url') or (request.get_json() or {}).get('url','')
    if not url: return jsonify({"action":"ALLOW"})
    if check_whitelist(url) or is_trusted_domain(url):
        return jsonify({"action":"ALLOW","verdict":"TRUSTED"})
    is_bl,matched = check_blacklist(url)
    if is_bl:
        save_scan(0,'proxy',url,"PHISHING","High","Blacklisted","Proxy",request.remote_addr)
        return jsonify({"action":"BLOCK","verdict":"PHISHING"})
    result = check_phishing_rules(url)
    action = "BLOCK" if result['verdict']=="PHISHING" else "ALLOW"
    save_scan(0,'proxy',url,result['verdict'],result['confidence'],result['explanation'],"Proxy",request.remote_addr)
    return jsonify({"action":action,"verdict":result['verdict']})

# -------------------------------------------------------
# ADMIN APIs
# -------------------------------------------------------
@app.route('/admin/users/add', methods=['POST'])
@admin_required
def add_user():
    data = request.get_json() or {}
    username = data.get('username','').strip()
    password = data.get('password','').strip()
    role = data.get('role','user')
    if not username or not password:
        return jsonify({"error":"Username and password required"}),400
    if len(password) < 6:
        return jsonify({"error":"Password min 6 characters"}),400
    if role not in ['user','admin']: role='user'
    try:
        conn = get_db()
        conn.execute('INSERT INTO users (username,password,role,created_at) VALUES (?,?,?,?)',
                     (username,hash_pass(password),role,now()))
        conn.commit(); conn.close()
        return jsonify({"success":True,"message":username+" added"})
    except:
        return jsonify({"error":"Username already exists"}),400

@app.route('/admin/users/delete/<int:uid>', methods=['DELETE'])
@admin_required
def delete_user(uid):
    if uid == session.get('user_id'):
        return jsonify({"error":"Cannot delete yourself"}),400
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id=?',(uid,))
    conn.commit(); conn.close()
    return jsonify({"success":True})

@app.route('/admin/whitelist/add', methods=['POST'])
@admin_required
def add_whitelist():
    data = request.get_json() or {}
    url = data.get('url','').strip()
    if not url: return jsonify({"error":"URL required"}),400
    try:
        conn = get_db()
        conn.execute('INSERT INTO whitelist (url,note,timestamp) VALUES (?,?,?)',(url,data.get('note',''),now()))
        conn.commit(); conn.close()
        return jsonify({"success":True})
    except: return jsonify({"error":"Already exists"}),400

@app.route('/admin/blacklist/add', methods=['POST'])
@admin_required
def add_blacklist():
    data = request.get_json() or {}
    url = data.get('url','').strip()
    if not url: return jsonify({"error":"URL required"}),400
    try:
        conn = get_db()
        conn.execute('INSERT INTO blacklist (url,note,timestamp) VALUES (?,?,?)',(url,data.get('note',''),now()))
        conn.commit(); conn.close()
        return jsonify({"success":True})
    except: return jsonify({"error":"Already exists"}),400

@app.route('/admin/whitelist/delete/<int:id>', methods=['DELETE'])
@admin_required
def del_whitelist(id):
    conn = get_db()
    conn.execute('DELETE FROM whitelist WHERE id=?',(id,))
    conn.commit(); conn.close()
    return jsonify({"success":True})

@app.route('/admin/blacklist/delete/<int:id>', methods=['DELETE'])
@admin_required
def del_blacklist(id):
    conn = get_db()
    conn.execute('DELETE FROM blacklist WHERE id=?',(id,))
    conn.commit(); conn.close()
    return jsonify({"success":True})

@app.route('/api/nca-stats')
def api_nca_stats():
    if NCA_ENABLED:
        return jsonify(get_nca_stats())
    return jsonify({'error': 'NCA engine not available'})

@app.route('/api/stats')
def api_stats():
    if session.get('role')=='admin': return jsonify(get_admin_stats())
    elif session.get('user_id'): return jsonify(get_user_stats(session['user_id']))
    conn = get_db()
    total = conn.execute('SELECT COUNT(*) as n FROM scans').fetchone()['n']
    ph = conn.execute("SELECT COUNT(*) as n FROM scans WHERE verdict='PHISHING'").fetchone()['n']
    conn.close()
    return jsonify({'total':total,'phishing':ph,'blacklist':0,'legitimate':0})

@app.route('/api/scans')
@login_required
def api_scans():
    conn = get_db()
    if session.get('role')=='admin':
        scans = conn.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 50').fetchall()
    else:
        scans = conn.execute('SELECT * FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 50',(session['user_id'],)).fetchall()
    conn.close()
    return jsonify([dict(s) for s in scans])

# -------------------------------------------------------
# RUN
# -------------------------------------------------------
init_db()

if __name__ == '__main__':
    print("\n"+"="*50)
    print("  AIPDA v4.0 - Enterprise Phishing Detection")
    print("="*50)
    print("  Portal:    http://localhost:5000")
    print("  Dashboard: http://localhost:5000/dashboard")
    print("  Admin:     admin / Admin@1234")
    print("="*50+"\n")
    app.run(debug=False, host='0.0.0.0', port=5000)
