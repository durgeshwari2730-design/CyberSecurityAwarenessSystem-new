from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3, re
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = "cyberguard-demo-key"
DB = "database.db"

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = db()
    c.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS quiz_results(id INTEGER PRIMARY KEY AUTOINCREMENT,user_email TEXT,score INTEGER,total INTEGER,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    c.commit(); c.close()

@app.route("/")
def home(): return render_template("index.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email=request.form.get("email","").strip().lower(); password=request.form.get("password","")
        c=db(); u=c.execute("SELECT * FROM users WHERE email=? AND password=?",(email,password)).fetchone(); c.close()
        if u:
            session["user"]=u["name"]; session["email"]=u["email"]; flash("Login successful!","success"); return redirect(url_for("home"))
        flash("Invalid email or password.","danger")
    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        name=request.form.get("name","").strip(); email=request.form.get("email","").strip().lower()
        password=request.form.get("password",""); confirm=request.form.get("confirm_password","")
        if not name or not email or not password: flash("Please fill all fields.","danger")
        elif "@" not in email: flash("Enter a valid email.","danger")
        elif len(password)<6: flash("Password must contain at least 6 characters.","danger")
        elif password!=confirm: flash("Passwords do not match.","danger")
        else:
            c=db()
            try:
                c.execute("INSERT INTO users(name,email,password) VALUES(?,?,?)",(name,email,password)); c.commit()
                flash("Registration successful. Please login.","success"); return redirect(url_for("login"))
            except sqlite3.IntegrityError: flash("Email already registered.","danger")
            finally: c.close()
    return render_template("register.html")

@app.route("/logout")
def logout(): session.clear(); flash("Logged out.","success"); return redirect(url_for("home"))

@app.route("/url-checker", methods=["GET","POST"])
def url_checker():
    result=None
    if request.method=="POST":
        raw=request.form.get("url","").strip()
        if not raw: result={"kind":"danger","title":"Invalid URL","message":"Please enter a URL.","reasons":[]}
        else:
            u=raw if re.match(r"^https?://",raw,re.I) else "http://"+raw
            p=urlparse(u); host=p.netloc.lower().split(":")[0]; score=0; reasons=[]
            if p.scheme!="https": score+=2; reasons.append("HTTPS is not used.")
            if "@" in u: score+=3; reasons.append("URL contains @ and may hide the destination.")
            if host.count(".")>=3: score+=1; reasons.append("Many subdomains detected.")
            if any(x in host for x in ["login","verify","update","secure","account","wallet","claim"]): score+=2; reasons.append("Suspicious keyword found in domain.")
            if host.endswith((".xyz",".top",".click",".tk",".gq")): score+=2; reasons.append("Domain uses a commonly abused TLD.")
            if len(u)>100: score+=1; reasons.append("URL is unusually long.")
            if score>=5: kind="danger"; title="Potentially Suspicious"; msg="Several phishing warning signs were detected."
            elif score>=2: kind="warning"; title="Use Caution"; msg="Some warning signs were detected."
            else: kind="success"; title="No Major Warning Signs"; msg="This basic checker found no common warning signs."
            result={"kind":kind,"title":title,"message":msg,"reasons":reasons}
    return render_template("url_checker.html",result=result)

@app.route("/email-analysis", methods=["GET","POST"])
def email_analysis():
    result=None
    if request.method=="POST":
        text=(request.form.get("subject","")+" "+request.form.get("body","")).lower()
        flags=[x for x in ["urgent","verify your account","click here","password","otp","winner","prize","bank","suspended","claim now","gift card","refund"] if x in text]
        links=re.findall(r"https?://\S+|www\.\S+",text,re.I)
        kind="danger" if len(flags)>=3 or len(links)>=3 else ("warning" if flags or links else "success")
        result={"kind":kind,"level":{"danger":"High Risk","warning":"Needs Caution","success":"Low Risk Signals"}[kind],"flags":flags,"links":links}
    return render_template("email_analysis.html",result=result)

QUESTIONS=[
("Which is the strongest password?",["password123","Vaishnavi@2026#Secure","12345678","qwerty"],1),
("What should you do with a suspicious link?",["Click it","Share it","Verify it first","Enter OTP"],2),
("What does MFA provide?",["Extra authentication layer","Faster internet","Free storage","Antivirus only"],0),
("What should never be shared with an unknown person?",["Public website","OTP and password","Weather","News"],1),
("HTTPS mainly helps protect data in transit using:",["Encryption","RAM","Battery","Screen"],0)]

@app.route("/quiz",methods=["GET","POST"])
def quiz():
    score=None
    if request.method=="POST":
        score=sum(int(request.form.get("q"+str(i),-1))==a for i,(_,_,a) in enumerate(QUESTIONS))
        if session.get("email"):
            c=db(); c.execute("INSERT INTO quiz_results(user_email,score,total) VALUES(?,?,?)",(session["email"],score,len(QUESTIONS))); c.commit(); c.close()
    return render_template("quiz.html",questions=QUESTIONS,score=score)

@app.route("/awareness")
def awareness(): return render_template("awareness.html")

@app.route("/dashboard")
def dashboard():
    if "email" not in session: flash("Please login first.","warning"); return redirect(url_for("login"))
    c=db(); results=c.execute("SELECT score,total,created_at FROM quiz_results WHERE user_email=? ORDER BY id DESC",(session["email"],)).fetchall(); c.close()
    return render_template("dashboard.html",results=results)

if __name__=="__main__":
    init_db()
    app.run(debug=True)
