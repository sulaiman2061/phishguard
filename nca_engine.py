import re
# =====================================================
# AIPDA - NCA Engine
# الهيئة الوطنية للأمن السيبراني - قاعدة بيانات محلية
# NCA = Ground Truth - لا يمكن تجاوزها
# =====================================================

import re
import urllib.parse

# -------------------------------------------------------
# NCA OFFICIAL DOMAINS - الدومينات الحكومية الرسمية
# المصدر: gov.sa + NCA ECC Framework
# -------------------------------------------------------

NCA_OFFICIAL_DOMAINS = {

    # ===== الجهات الحكومية =====
    "gov.sa", "nca.gov.sa", "moi.gov.sa", "mol.gov.sa",
    "moh.gov.sa", "moe.gov.sa", "mcit.gov.sa", "my.gov.sa",
    "zatca.gov.sa", "sama.gov.sa", "cma.org.sa", "sdaia.gov.sa",
    "vision2030.gov.sa", "spa.gov.sa", "saudiembassy.net",
    "moci.gov.sa", "misk.org.sa", "hrsd.gov.sa",
    "mewa.gov.sa", "moenergy.gov.sa", "mof.gov.sa",
    "stats.gov.sa", "nauss.edu.sa", "rcrc.gov.sa",
    "saudiexchange.sa", "pif.gov.sa", "neom.com",

    # ===== خدمات حكومية رقمية =====
    "absher.sa", "nafath.sa", "elm.sa", "etimad.sa",
    "sadad.sa", "tawakkalna.com.sa", "sehhaty.com.sa",
    "muqeem.sa", "iqama.net", "enjaz.com.sa",
    "naqaa.com.sa", "balady.com.sa", "saudigov.sa",
    "digital.gov.sa", "nic.sa", "citc.gov.sa",

    # ===== البنوك السعودية الرسمية =====
    "alrajhibank.com.sa", "alrajhi.com.sa",
    "sab.com", "sab.com.sa",
    "riyadbank.com", "riyadbank.com.sa",
    "anb.com.sa", "arabbank.com.sa",
    "bsf.com.sa", "fransabank.com",
    "alinma.com", "alinma.com.sa",
    "bankalbilad.com.sa", "bilad.com.sa",
    "jazirabank.com", "bankaljazira.com.sa",
    "ncb.com.sa", "alahli.com", "ahl.com.sa",
    "stcbank.com.sa", "stcpay.com.sa",
    "tabby.ai", "tamara.co",
    "saudidigitalbank.com.sa",

    # ===== الاتصالات =====
    "stc.com.sa", "mobily.com.sa", "zain.com.sa",
    "solutions.com.sa", "stc.sa",

    # ===== التعليم =====
    "ksu.edu.sa", "kau.edu.sa", "kfupm.edu.sa",
    "kku.edu.sa", "uqu.edu.sa", "taibahu.edu.sa",
    "arabeast.edu.sa", "iau.edu.sa", "su.edu.sa",
    "pmu.edu.sa", "alfaisal.edu", "dar.edu.sa",
    "effatuniversity.edu.sa", "tumt.edu.sa",

    # ===== الصحة والطوارئ =====
    "moh.gov.sa", "ngha.med.sa", "ksrelief.org",
    "srca.org.sa", "saudivision.com",

    # ===== الطاقة والصناعة =====
    "aramco.com", "saudiaramco.com", "sabic.com",
    "sec.org.sa", "maaden.com.sa", "nupco.com.sa",
    "hadeed.com.sa",

    # ===== التجارة والاقتصاد =====
    "saudiexchange.sa", "tadawul.com.sa",
    "monsha-at.gov.sa", "sdb.gov.sa",
    "mc.gov.sa", "mci.gov.sa",

    # ===== الترفيه والثقافة =====
    "gea.gov.sa", "sfa.gov.sa", "scta.gov.sa",
    "sacf.com.sa", "visitsaudi.com",

    # ===== المواصلات والبنية التحتية =====
    "saudiairlines.com", "flynass.com",
    "haramainrailway.com", "sar.com.sa",
    "nca.gov.sa", "momra.gov.sa",
}

# -------------------------------------------------------
# NCA PHISHING PATTERNS - أنماط التصيد المعروفة
# مبنية على تقارير NCA الرسمية
# -------------------------------------------------------

NCA_PHISHING_PATTERNS = [

    # انتحال جهات حكومية
    (r"absher[-_.](?!sa\b)|absh3r|abs4er|4bsher|absher-login",
     "NCA-001", "Fake Absher portal", 10),

    (r"nafath[-_.](?!sa\b)|naf4th|n4fath|nafaath-verify",
     "NCA-001", "Fake Nafath identity service", 10),

    (r"zatca[-_.](?!gov)|zakat-verify|zatca-secure|zak4ta",
     "NCA-001", "Fake ZATCA tax authority", 10),

    (r"elm[-_.](?!sa\b)|3lm-sa|elm-verify|elm-login",
     "NCA-001", "Fake Elm digital services", 10),

    (r"sadad[-_.](?!sa\b)|s4dad|sadad-verify|sadad-payment",
     "NCA-001", "Fake SADAD payment system", 10),

    (r"moi[-_.](?!gov)|moi-verify|m0i-sa|moi-login",
     "NCA-001", "Fake Ministry of Interior", 10),

    (r"stcpay[-_.](?!com\.sa)|stc-pay-verify|stcpay-transfer",
     "NCA-001", "Fake STC Pay service", 10),

    (r"etimad[-_.](?!gov)|e-timad|etim4d",
     "NCA-001", "Fake Etimad government platform", 10),

    # انتحال بنوك سعودية
    (r"alrajh[i1][-_.](?!com\.sa)|rajhi-secure|4lrajhi",
     "NCA-002", "Fake Al Rajhi Bank", 10),

    (r"s[a4]b[-_.](?!com)|sab-bank-verify|sab-secure",
     "NCA-002", "Fake SAB (Saudi British Bank)", 10),

    (r"r[i1]yadbank(?!\.com)|riyad-bank-secure|riyadbank-verify",
     "NCA-002", "Fake Riyad Bank", 10),

    (r"alinma[-_.](?!com)|al[i1]nma-bank|alinma-verify",
     "NCA-002", "Fake Alinma Bank", 10),

    (r"ncb[-_.](?!com\.sa)|ncb-bank-verify|alahl[i1]-verify",
     "NCA-002", "Fake NCB / Al Ahli Bank", 10),

    (r"bankalbilad[-_.](?!com\.sa)|bilad-verify",
     "NCA-002", "Fake Bank AlBilad", 10),

    # انتحال تجارة إلكترونية سعودية
    (r"noon[-_.](?!com(?:\.sa)?)|no0n-shop|noon-verify",
     "NCA-003", "Fake Noon e-commerce", 8),

    (r"jarir[-_.](?!com\.sa)|jar[i1]r-shop|jarir-verify",
     "NCA-003", "Fake Jarir Bookstore", 8),

    (r"extra[-_.](?!com\.sa)|3xtra-shop|extra-verify",
     "NCA-003", "Fake Extra Electronics", 8),

    # هجمات بالعربية
    (r"تحقق من حسابك|حسابك مع[لق]|تم تعليق حسابك",
     "NCA-005", "Arabic account suspension phishing", 8),

    (r"فوز|جائزة|ربحت|مبروك.*فزت|اضغط.*فوراً",
     "NCA-005", "Arabic prize/lottery phishing", 7),

    (r"أدخل.*كلمة المرور|رقم البطاقة|الرقم السري",
     "NCA-005", "Arabic credential harvesting", 9),

    # روابط مشبوهة عامة
    (r"\.sa\.[a-z]{2,4}[/\s]",
     "NCA-004", "Fake .sa domain pattern", 7),

    (r"ksa[-_](?:verify|secure|login|bank|gov)",
     "NCA-004", "Suspicious KSA prefix domain", 6),

    (r"saudi[-_](?:gov|bank|pay|secure)[-_.](?!gov\.sa)",
     "NCA-004", "Suspicious Saudi entity impersonation", 7),
]


def extract_domain(text):
    """استخراج الدومين من الرابط"""
    try:
        text = text.strip().lower()
        if text.startswith('http'):
            parsed = urllib.parse.urlparse(text)
            domain = parsed.netloc
        else:
    
            match = re.search(r'https?://([^/\s?#]+)', text)
            domain = match.group(1) if match else text
        domain = re.sub(r'^www\.', '', domain).split(':')[0]
        return domain.lower().strip()
    except:
        return ''


def is_nca_official(text):
    """
    التحقق إذا الرابط من جهة رسمية معتمدة من NCA
    هذا يتجاوز الـ Whitelist والـ Blacklist
    لا يمكن للأدمن تغيير هذا
    """
    domain = extract_domain(text)
    if not domain:
        return False, None

    # تحقق مباشر
    if domain in NCA_OFFICIAL_DOMAINS:
        return True, domain

    # تحقق من subdomain
    for official in NCA_OFFICIAL_DOMAINS:
        if domain.endswith('.' + official):
            return True, official

    # تحقق من .gov.sa
    if domain.endswith('.gov.sa'):
        return True, domain

    # تحقق من .edu.sa
    if domain.endswith('.edu.sa'):
        return True, domain

    return False, None


def check_nca_phishing(text):
    """
    كشف أنماط التصيد المعروفة من تقارير NCA
    هذا يتجاوز الـ Whitelist أيضاً
    إذا الأدمن حط دومين تصيد بالـ Whitelist → NCA تكشفه
    """
    text_lower = text.lower()
    nca_flags = []

    for pattern, rule_id, description, weight in NCA_PHISHING_PATTERNS:
        if re.search(pattern, text_lower):
            nca_flags.append({
                "rule": rule_id,
                "description": description,
                "weight": weight
            })

    return nca_flags


def analyze_with_nca(text):
    """
    التحليل الكامل بـ NCA
    يرجع dict فيه النتيجة
    """
    # 1. هل هو رسمي؟
    is_official, matched_domain = is_nca_official(text)
    if is_official:
        return {
            "nca_result": "OFFICIAL",
            "verdict": "LEGITIMATE",
            "confidence": "High",
            "explanation": "Verified official domain by NCA database: " + str(matched_domain),
            "nca_flags": [],
            "method": "NCA Official Database",
            "nca_rule": "OFFICIAL"
        }

    # 2. هل فيه أنماط تصيد NCA؟
    nca_flags = check_nca_phishing(text)
    if nca_flags:
        top_flag = nca_flags[0]
        total_weight = sum(f['weight'] for f in nca_flags)
        return {
            "nca_result": "PHISHING",
            "verdict": "PHISHING",
            "confidence": "High" if total_weight >= 8 else "Medium",
            "explanation": "NCA threat detected: " + top_flag['description'] + " [Rule: " + top_flag['rule'] + "]",
            "nca_flags": [f['description'] for f in nca_flags],
            "method": "NCA Threat Intelligence",
            "nca_rule": top_flag['rule']
        }

    # 3. لا رسمي ولا تصيد NCA معروف
    return {
        "nca_result": "UNKNOWN",
        "verdict": None,
        "nca_flags": [],
        "method": None
    }


def get_nca_stats():
    """إحصائيات قاعدة NCA"""
    return {
        "official_domains": len(NCA_OFFICIAL_DOMAINS),
        "phishing_patterns": len(NCA_PHISHING_PATTERNS),
        "categories": ["ECC-1 Gov", "ECC-2 Banking", "ECC-3 E-commerce",
                       "ECC-4 Domains", "ECC-5 Social Engineering"]
    }
