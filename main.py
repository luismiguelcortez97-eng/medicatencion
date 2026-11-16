import os,sqlite3,hashlib,secrets,hmac
from datetime import datetime,timedelta,date
from fastapi import FastAPI,HTTPException,Header,Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,Field
DB=os.getenv("DATABASE_PATH","control_financiero.db"); SECRET=os.getenv("APP_SECRET")
if not SECRET: raise RuntimeError("APP_SECRET no configurado")
app=FastAPI(title="Control Financiero Personal",version="2.1.0")
app.mount("/static",StaticFiles(directory="static"),name="static")
def con():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;return c
with con() as c:
 c.executescript("""CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,salt TEXT,hash TEXT);
 CREATE TABLE IF NOT EXISTS businesses(id INTEGER PRIMARY KEY,name TEXT UNIQUE);
 CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY,name TEXT,kind TEXT,scope TEXT,business_id INTEGER,balance REAL);
 CREATE TABLE IF NOT EXISTS movements(id INTEGER PRIMARY KEY,kind TEXT,scope TEXT,concept TEXT,amount REAL,day TEXT,account_id INTEGER,dest_id INTEGER,business_id INTEGER,category TEXT);
 CREATE TABLE IF NOT EXISTS debts(id INTEGER PRIMARY KEY,creditor TEXT,scope TEXT,business_id INTEGER,balance REAL,rate REAL,min_payment REAL,due_day INTEGER);
 CREATE TABLE IF NOT EXISTS obligations(id INTEGER PRIMARY KEY,name TEXT,scope TEXT,amount REAL,due_date TEXT,paid INTEGER DEFAULT 0);
 CREATE TABLE IF NOT EXISTS budgets(id INTEGER PRIMARY KEY,name TEXT,scope TEXT,category TEXT,monthly_limit REAL);""")
def auth(authorization:str|None=Header(default=None)):
 try:
  if not authorization or not authorization.startswith("Bearer "): raise ValueError()
  u,e,s=authorization[7:].split(".");p=u+":"+e
  if int(e)<int(datetime.utcnow().timestamp()) or not hmac.compare_digest(s,hmac.new(SECRET.encode(),p.encode(),hashlib.sha256).hexdigest()): raise ValueError()
  with con() as c:
   if not c.execute("SELECT id FROM users WHERE username=?",(u,)).fetchone(): raise ValueError()
  return u
 except Exception: raise HTTPException(401,"Sesión inválida")
def make_token(u):
 e=str(int((datetime.utcnow()+timedelta(hours=12)).timestamp()));p=u+":"+e
 return p+"."+hmac.new(SECRET.encode(),p.encode(),hashlib.sha256).hexdigest()
class Cred(BaseModel):
 username:str=Field(min_length=3,max_length=60);password:str=Field(min_length=12,max_length=200)
class Data(BaseModel): data:dict
@app.get("/")
def home(): return FileResponse("static/index.html")
@app.post("/api/register")
def register(x:Cred):
 salt=secrets.token_hex(16);h=hashlib.pbkdf2_hmac("sha256",x.password.encode(),bytes.fromhex(salt),310000).hex()
 with con() as c:
  if c.execute("SELECT 1 FROM users").fetchone(): raise HTTPException(403,"Registro inicial cerrado")
  c.execute("INSERT INTO users(username,salt,hash) VALUES(?,?,?)",(x.username,salt,h))
 return {"ok":True}
@app.post("/api/login")
def login(x:Cred):
 with con() as c:u=c.execute("SELECT * FROM users WHERE username=?",(x.username,)).fetchone()
 if not u or not hmac.compare_digest(hashlib.pbkdf2_hmac("sha256",x.password.encode(),bytes.fromhex(u["salt"]),310000).hex(),u["hash"]):raise HTTPException(401,"Credenciales incorrectas")
 return {"token":make_token(x.username)}
@app.get("/api/data")
def data(user=Depends(auth)):
 with con() as c:return {t:[dict(r) for r in c.execute("SELECT * FROM "+t)] for t in ("businesses","accounts","movements","debts","obligations","budgets")}
@app.post("/api/{table}")
def add(table:str,x:Data,user=Depends(auth)):
 fields={"businesses":["name"],"accounts":["name","kind","scope","business_id","balance"],"movements":["kind","scope","concept","amount","day","account_id","dest_id","business_id","category"],"debts":["creditor","scope","business_id","balance","rate","min_payment","due_day"],"obligations":["name","scope","amount","due_date"],"budgets":["name","scope","category","monthly_limit"]}
 if table not in fields:raise HTTPException(404,"Sección inválida")
 d=x.data;ks=fields[table]
 if any(k not in d for k in ks):raise HTTPException(422,"Faltan campos")
 with con() as c:r=c.execute("INSERT INTO "+table+"("+",".join(ks)+") VALUES("+",".join("?" for _ in ks)+")",[d[k] for k in ks])
 return {"id":r.lastrowid}
@app.post("/api/obligations/{oid}/paid")
def paid(oid:int,user=Depends(auth)):
 with con() as c:
  if not c.execute("UPDATE obligations SET paid=1 WHERE id=?",(oid,)).rowcount:raise HTTPException(404,"No encontrada")
 return {"ok":True}
@app.get("/api/dashboard")
def dashboard(user=Depends(auth)):
 m=date.today().strftime("%Y-%m")
 with con() as c:
  q=lambda sql,args=():c.execute(sql,args).fetchone()[0] or 0
  return {"cash":q("SELECT SUM(balance) FROM accounts WHERE scope='personal'"),"debt":q("SELECT SUM(balance) FROM debts WHERE scope='personal'"),"income":q("SELECT SUM(amount) FROM movements WHERE kind='income' AND scope='personal' AND substr(day,1,7)=?",(m,)),"expense":q("SELECT SUM(amount) FROM movements WHERE kind='expense' AND scope='personal' AND substr(day,1,7)=?",(m,)),"obligations":q("SELECT COUNT(*) FROM obligations WHERE paid=0")}
@app.post("/api/travis")
def travis(x:Data,user=Depends(auth)):
 d=dashboard(user);q=str(x.data.get("question",""))[:1000]
 a=("Soy Travis. Cuentas personales $ {0:,.2f}; deuda $ {1:,.2f}; ingresos del mes $ {2:,.2f}; gastos $ {3:,.2f}; obligaciones pendientes {4}. Protege vencimientos y pagos mínimos antes de acelerar deudas. No consideres libre dinero reservado ni ingresos empresariales como personales. Pregunta: {5}").format(d["cash"],d["debt"],d["income"],d["expense"],d["obligations"],q)
 return {"answer":a}
@app.get("/api/export")
def export(user=Depends(auth)):return data(user)
