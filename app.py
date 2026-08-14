from flask import Flask, render_template, request, jsonify, send_file
from urllib.parse import urlparse
import socket, ssl, urllib.request, hashlib, os, io, datetime, uuid, json, re

app = Flask(__name__)
MAX_UPLOAD = 10 * 1024 * 1024

HEADERS = {
    "strict-transport-security": ("Strict-Transport-Security", "MEDIUM"),
    "content-security-policy": ("Content-Security-Policy", "MEDIUM"),
    "x-content-type-options": ("X-Content-Type-Options", "LOW"),
    "x-frame-options": ("X-Frame-Options", "LOW"),
    "referrer-policy": ("Referrer-Policy", "LOW"),
    "permissions-policy": ("Permissions-Policy", "LOW"),
}

def now():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"

def normalize(value):
    value = (value or "").strip()
    if not value:
        raise ValueError("Target is required.")
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    p = urlparse(value)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Enter a valid HTTP(S) target.")
    return p

def risk_score(findings):
    score = 100
    for f in findings:
        score -= {"CRITICAL":25,"HIGH":18,"MEDIUM":10,"LOW":4,"INFO":0}.get(f["severity"], 2)
    score = max(0, min(100, score))
    risk = "LOW" if score >= 85 else "MODERATE" if score >= 65 else "HIGH" if score >= 40 else "CRITICAL"
    return score, risk

def web_scan(target):
    p = normalize(target)
    host = p.hostname
    port = p.port or (443 if p.scheme == "https" else 80)
    findings, checks, technologies = [], [], []
    ips = []
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ips = sorted({x[4][0] for x in infos})
        checks.append({"name":"DNS resolution","status":"PASS","detail":f"{len(ips)} address(es) resolved."})
    except Exception as e:
        checks.append({"name":"DNS resolution","status":"FAIL","detail":"Host could not be resolved."})
        findings.append({"severity":"HIGH","title":"DNS resolution failed","evidence":str(e)[:160],"remediation":"Verify DNS records and the target hostname."})
        score,risk=risk_score(findings)
        return make_result(p, ips, checks, findings, technologies, score, risk)

    # Passive DNS intelligence
    dns = {"hostname":host, "addresses":ips[:10], "port":port}

    # TLS inspection
    tls = {"enabled": p.scheme == "https"}
    if p.scheme == "https":
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host,443),timeout=7) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    cert=s.getpeercert()
                    tls["version"]=s.version()
                    tls["cipher"]=s.cipher()[0] if s.cipher() else "Unknown"
                    tls["subject"]=dict(x[0] for x in cert.get("subject",[])).get("commonName","")
                    checks.append({"name":"TLS connection","status":"PASS","detail":f"{tls['version']} / {tls['cipher']}"})
        except Exception as e:
            checks.append({"name":"TLS connection","status":"FAIL","detail":"TLS validation failed."})
            findings.append({"severity":"HIGH","title":"TLS validation failed","evidence":str(e)[:160],"remediation":"Verify certificate chain, hostname and TLS configuration."})
    else:
        findings.append({"severity":"MEDIUM","title":"Target uses plain HTTP","evidence":p.geturl(),"remediation":"Use HTTPS for production traffic and sensitive data."})
        checks.append({"name":"Transport security","status":"WARN","detail":"Target URL is HTTP."})

    headers={}
    try:
        req=urllib.request.Request(p.geturl(),headers={"User-Agent":"CyberForge-Defensive-Audit/1.0"})
        ctx=ssl.create_default_context()
        with urllib.request.urlopen(req,timeout=9,context=ctx) as resp:
            headers={k.lower():v for k,v in resp.headers.items()}
            body=resp.read(120000).decode("utf-8","ignore")
            final_url=resp.geturl()
            status=resp.status
            server=resp.headers.get("Server","Not disclosed")
            ctype=resp.headers.get("Content-Type","")
            checks.append({"name":"HTTP response","status":"PASS","detail":f"HTTP {status}"})
            # Safe technology fingerprinting based on visible headers/content
            tech=[]
            powered=resp.headers.get("X-Powered-By")
            if powered: tech.append(powered)
            low=body.lower()
            for needle,label in [("wp-content","WordPress"),("next/static","Next.js"),("__next","Next.js"),("react","React"),("vue","Vue.js"),("drupal","Drupal")]:
                if needle in low and label not in tech: tech.append(label)
            if "cloudflare" in resp.headers.get("Server","").lower(): tech.append("Cloudflare")
            technologies=sorted(set(tech))
            for key,(label,severity) in HEADERS.items():
                if key in headers:
                    checks.append({"name":label,"status":"PASS","detail":"Header present."})
                else:
                    checks.append({"name":label,"status":"WARN","detail":"Header not observed."})
                    findings.append({"severity":severity,"title":f"Missing {label}","evidence":"HTTP response did not expose the header.","remediation":f"Review and configure an appropriate {label} policy for the application."})
            if "server" in headers:
                checks.append({"name":"Server disclosure","status":"INFO","detail":"Server header is visible."})
            if final_url != p.geturl():
                checks.append({"name":"Redirects","status":"INFO","detail":f"Final URL: {final_url}"})
    except Exception as e:
        checks.append({"name":"HTTP response","status":"FAIL","detail":"Request failed."})
        findings.append({"severity":"HIGH","title":"HTTP audit failed","evidence":str(e)[:180],"remediation":"Verify that the service is reachable and correctly configured."})
        final_url=p.geturl(); status=None; server="Unknown"; ctype="Unknown"

    score,risk=risk_score(findings)
    return make_result(p,ips,checks,findings,technologies,score,risk,dns=dns,tls=tls,status=status,server=server,content_type=ctype)

def make_result(p,ips,checks,findings,technologies,score,risk,dns=None,tls=None,status=None,server=None,content_type=None):
    return {
        "scan_id":"CF-"+uuid.uuid4().hex[:10].upper(),
        "target":p.geturl(),"hostname":p.hostname,"timestamp":now(),
        "ips":ips,"dns":dns or {},"tls":tls or {},
        "technologies":technologies,"checks":checks,"findings":findings,
        "score":score,"risk":risk,"status_code":status,
        "server":server,"content_type":content_type
    }

def file_scan(file):
    data=file.read(MAX_UPLOAD+1)
    if len(data)>MAX_UPLOAD: raise ValueError("File exceeds the 10 MB limit.")
    sha256=hashlib.sha256(data).hexdigest()
    sha1=hashlib.sha1(data).hexdigest()
    md5=hashlib.md5(data).hexdigest()
    name=os.path.basename(file.filename or "uploaded-file")
    ext=os.path.splitext(name)[1].lower() or "none"
    findings=[]
    # Conservative static indicators; no execution.
    suspicious_ext={".exe",".dll",".scr",".bat",".cmd",".ps1",".vbs",".js",".jar",".apk"}
    if ext in suspicious_ext:
        findings.append({"severity":"INFO","title":"Executable/script-like file type","evidence":ext,"remediation":"Verify the source and scan the file with a trusted malware reputation service before opening."})
    score,risk=risk_score(findings)
    return {"scan_id":"CF-FILE-"+uuid.uuid4().hex[:8].upper(),"filename":name,"size":len(data),
            "extension":ext,"sha256":sha256,"sha1":sha1,"md5":md5,"findings":findings,
            "score":score,"risk":risk,"timestamp":now(),
            "virustotal":{"configured":bool(os.getenv("VIRUSTOTAL_API_KEY")),"status":"API integration ready" if os.getenv("VIRUSTOTAL_API_KEY") else "API key not configured"}}

def ai_explain(payload):
    findings=payload.get("findings",[])
    if not findings:
        return {"summary":"No findings were supplied. The enabled checks did not identify an actionable issue.","priorities":[]}
    priorities=[]
    for f in findings[:5]:
        priorities.append({"title":f.get("title"),"severity":f.get("severity"),"action":f.get("remediation","Review the finding and apply a secure configuration.")})
    high=sum(1 for f in findings if f.get("severity") in ("CRITICAL","HIGH"))
    summary=f"{len(findings)} finding(s) were identified. {high} are high-priority. Address the highest-severity items first, validate the change, then rerun the audit."
    return {"summary":summary,"priorities":priorities}

@app.get("/")
def index(): return render_template("index.html")

@app.post("/api/scan")
def api_scan():
    try:
        data=request.get_json(silent=True) or {}
        return jsonify(web_scan(data.get("target","")))
    except ValueError as e: return jsonify({"error":str(e)}),400
    except Exception as e: return jsonify({"error":"Scanner error: "+str(e)[:120]}),500

@app.post("/api/file-scan")
def api_file():
    try:
        f=request.files.get("file")
        if not f: return jsonify({"error":"Choose a file."}),400
        return jsonify(file_scan(f))
    except ValueError as e: return jsonify({"error":str(e)}),400

@app.post("/api/ai-explain")
def api_ai():
    try:
        return jsonify(ai_explain(request.get_json(silent=True) or {}))
    except Exception: return jsonify({"error":"Assistant could not process the findings."}),500

@app.post("/api/report")
def report():
    data=request.get_json(silent=True) or {}
    # A lightweight HTML report that can be printed to PDF by the browser.
    html=render_template("report.html", data=data)
    return jsonify({"html":html,"filename":(data.get("scan_id") or "cyberforge-report")+".html"})

@app.get("/health")
def health(): return jsonify({"status":"ok","service":"CyberForge","time":now()})

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.getenv("PORT",5000)))
