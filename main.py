import os, hmac, hashlib, secrets
from datetime import datetime, timedelta, date
from contextlib import contextmanager
from pathlib import Path
import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DB = os.getenv("DATABASE_URL")
SECRET = os.getenv("APP_SECRET")
if not DB:
    raise RuntimeError("Falta DATABASE_URL: configura PostgreSQL exclusivo para Finanzas.")
if not SECRET or len(SECRET) < 32:
    raise RuntimeError("APP_SECRET debe tener al menos 32 caracteres.")
app = FastAPI(title="Finanzas · Travis", version="3.0.0")
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

@contextmanager
def con():
    with psycopg.connect(DB, sslmode="require", row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            yield cur

def init_db():
    sqls = [
    """CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY,username TEXT UNIQUE NOT NULL,salt TEXT NOT NULL,hash TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS businesses(id BIGSERIAL PRIMARY KEY,name TEXT UNIQUE NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS accounts(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,scope TEXT NOT NULL,business_id BIGINT REFERENCES businesses(id),balance DOUBLE PRECISION NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS movements(id BIGSERIAL PRIMARY KEY,kind TEXT NOT NULL,scope TEXT NOT NULL,concept TEXT NOT NULL,amount DOUBLE PRECISION NOT NULL CHECK(amount>0),day TEXT NOT NULL,account_id BIGINT REFERENCES accounts(id),dest_id BIGINT REFERENCES accounts(id),business_id BIGINT REFERENCES businesses(id),category TEXT)""",
    """CREATE TABLE IF NOT EXISTS debts(id BIGSERIAL PRIMARY KEY,creditor TEXT NOT NULL,scope TEXT NOT NULL,business_id BIGINT REFERENCES businesses(id),balance DOUBLE PRECISION NOT NULL DEFAULT 0,rate DOUBLE PRECISION DEFAULT 0,min_payment DOUBLE PRECISION DEFAULT 0,due_day INTEGER)""",
    """CREATE TABLE IF NOT EXISTS obligations(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL,scope TEXT NOT NULL,amount DOUBLE PRECISION NOT NULL,due_date TEXT NOT NULL,paid INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS budgets(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL,scope TEXT NOT NULL,category TEXT NOT NULL,monthly_limit DOUBLE PRECISION NOT NULL)"""
    ]
    with con() as c:
        for s in sqls: c.execute(s)
init_db()

def auth(authorization: str | None = Header(default=None)):
    try:
        if not authorization or not authorization.startswith("Bearer "): raise ValueError()
        u, exp, sig = authorization[7:].split(".", 2)
        payload = u + ":" + exp
        expected = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if int(exp) < int(datetime.utcnow().timestamp()) or not hmac.compare_digest(sig, expected): raise ValueError()
        with con() as c:
            c.execute("SELECT id FROM users WHERE username=%s", (u,))
            if not c.fetchone(): raise ValueError()
        return u
    except Exception: raise HTTPException(401, "Sesión inválida o vencida. Ingresa de nuevo.")

def make_token(u):
    exp = str(int((datetime.utcnow()+timedelta(hours=12)).timestamp()))
    payload = u+":"+exp
    return payload+"."+hmac.new(SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest()

class Cred(BaseModel):
    username: str = Field(min_length=3,max_length=60,pattern=r"^[\w.-]+$")
    password: str = Field(min_length=12,max_length=200)
class Data(BaseModel):
    data: dict

def valid_scope(v):
    if v not in ("personal","business"): raise HTTPException(422,"Clasificación inválida.")
    return v
def valid_amount(v):
    try: n=float(v)
    except: raise HTTPException(422,"Cantidad inválida.")
    if n<=0 or n>1000000000: raise HTTPException(422,"La cantidad debe ser mayor que cero.")
    return n
def get_account(c,i,sc=None):
    if not i: raise HTTPException(422,"Selecciona una cuenta.")
    c.execute("SELECT * FROM accounts WHERE id=%s",(i,)); a=c.fetchone()
    if not a: raise HTTPException(404,"Cuenta no encontrada.")
    if sc and a["scope"]!=sc: raise HTTPException(422,"La cuenta no corresponde a ese movimiento.")
    return a

def apply_movement(c,d):
    k=d["kind"]; n=d["amount"]; src=d.get("account_id"); dst=d.get("dest_id"); sc=d["scope"]
    if k=="income":
        a=get_account(c,dst,sc)
        if sc=="business" and a["business_id"]!=d.get("business_id"): raise HTTPException(422,"El ingreso debe pertenecer al negocio seleccionado.")
        c.execute("UPDATE accounts SET balance=balance+%s WHERE id=%s",(n,dst))
    elif k=="expense":
        a=get_account(c,src,sc)
        if sc=="business" and a["business_id"]!=d.get("business_id"): raise HTTPException(422,"El gasto debe salir de la cuenta del negocio.")
        if a["balance"]<n: raise HTTPException(422,"Saldo insuficiente en la cuenta.")
        c.execute("UPDATE accounts SET balance=balance-%s WHERE id=%s",(n,src))
    elif k=="transfer":
        a=get_account(c,src); b=get_account(c,dst)
        if a["scope"]!=b["scope"] or a["scope"]!=sc: raise HTTPException(422,"La transferencia debe permanecer dentro de la misma caja.")
        if sc=="business" and a["business_id"]!=b["business_id"]: raise HTTPException(422,"No mezcles cuentas de negocios diferentes.")
        if a["balance"]<n: raise HTTPException(422,"Saldo insuficiente en la cuenta de origen.")
        c.execute("UPDATE accounts SET balance=balance-%s WHERE id=%s",(n,src))
        c.execute("UPDATE accounts SET balance=balance+%s WHERE id=%s",(n,dst))
    elif k=="withdrawal":
        a=get_account(c,src,"business"); get_account(c,dst,"personal")
        if not d.get("business_id") or a["business_id"]!=d["business_id"]: raise HTTPException(422,"Selecciona el negocio de origen.")
        if a["balance"]<n: raise HTTPException(422,"Saldo insuficiente en el negocio.")
        c.execute("UPDATE accounts SET balance=balance-%s WHERE id=%s",(n,src))
        c.execute("UPDATE accounts SET balance=balance+%s WHERE id=%s",(n,dst))
    else: raise HTTPException(422,"Tipo de movimiento inválido.")

@app.get("/")
def home(): return FileResponse(str(STATIC/"index.html"))
@app.get("/health")
def health():
    with con() as c: c.execute("SELECT 1"); c.fetchone()
    return {"ok":True,"database":"PostgreSQL","app":"Finanzas"}
@app.post("/api/register")
def register(x:Cred):
    salt=secrets.token_hex(16)
    hashed=hashlib.pbkdf2_hmac("sha256",x.password.encode(),bytes.fromhex(salt),310000).hex()
    with con() as c:
        c.execute("SELECT 1 FROM users LIMIT 1")
        if c.fetchone(): raise HTTPException(403,"El usuario propietario ya existe.")
        c.execute("INSERT INTO users(username,salt,hash) VALUES(%s,%s,%s)",(x.username,salt,hashed))
    return {"ok":True}
@app.post("/api/login")
def login(x:Cred):
    with con() as c: c.execute("SELECT * FROM users WHERE username=%s",(x.username,)); u=c.fetchone()
    if not u or not hmac.compare_digest(hashlib.pbkdf2_hmac("sha256",x.password.encode(),bytes.fromhex(u["salt"]),310000).hex(),u["hash"]):
        raise HTTPException(401,"Usuario o contraseña incorrectos.")
    return {"token":make_token(x.username)}
@app.get("/api/data")
def get_data(user=Depends(auth)):
    with con() as c:
        out={}
        for t in ("businesses","accounts","movements","debts","obligations","budgets"):
            c.execute("SELECT * FROM "+t+" ORDER BY id DESC"); out[t]=c.fetchall()
        return out

@app.post("/api/{table}")
def add(table:str,x:Data,user=Depends(auth)):
    d=x.data
    with con() as c:
        if table=="businesses":
            name=str(d.get("name") or "").strip()
            if not name: raise HTTPException(422,"Escribe el nombre del negocio.")
            c.execute("INSERT INTO businesses(name) VALUES(%s) RETURNING id",(name,))
        elif table=="accounts":
            sc=valid_scope(d.get("scope")); name=str(d.get("name") or "").strip()
            if not name: raise HTTPException(422,"Escribe el nombre de la cuenta.")
            bid=d.get("business_id") if sc=="business" else None
            if sc=="business":
                c.execute("SELECT id FROM businesses WHERE id=%s",(bid,))
                if not c.fetchone(): raise HTTPException(422,"Registra primero el negocio.")
            bal=float(d.get("balance") or 0)
            if bal<0: raise HTTPException(422,"Saldo inicial no válido.")
            c.execute("INSERT INTO accounts(name,kind,scope,business_id,balance) VALUES(%s,%s,%s,%s,%s) RETURNING id",(name,d.get("kind") or "bank",sc,bid,bal))
        elif table=="movements":
            sc=valid_scope(d.get("scope")); n=valid_amount(d.get("amount")); k=d.get("kind")
            day=str(d.get("day") or date.today().isoformat())
            try: datetime.strptime(day,"%Y-%m-%d")
            except: raise HTTPException(422,"Fecha inválida.")
            item={"kind":k,"scope":sc,"amount":n,"account_id":d.get("account_id"),"dest_id":d.get("dest_id"),"business_id":d.get("business_id")}
            apply_movement(c,item)
            c.execute("INSERT INTO movements(kind,scope,concept,amount,day,account_id,dest_id,business_id,category) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (k,sc,str(d.get("concept") or "Sin concepto").strip(),n,day,item["account_id"],item["dest_id"],item["business_id"],d.get("category") or "General"))
        elif table=="debts":
            creditor=str(d.get("creditor") or "").strip()
            if not creditor: raise HTTPException(422,"Escribe el acreedor.")
            sc=valid_scope(d.get("scope")); n=valid_amount(d.get("balance")); rate=max(0,float(d.get("rate") or 0)); minimum=max(0,float(d.get("min_payment") or 0)); due=d.get("due_day")
            if due is not None and not 1<=int(due)<=31: raise HTTPException(422,"Día de pago entre 1 y 31.")
            c.execute("INSERT INTO debts(creditor,scope,business_id,balance,rate,min_payment,due_day) VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING id",(creditor,sc,d.get("business_id") if sc=="business" else None,n,rate,minimum,due))
        elif table=="obligations":
            name=str(d.get("name") or "").strip(); due=str(d.get("due_date") or "")
            if not name: raise HTTPException(422,"Escribe la obligación.")
            try: datetime.strptime(due,"%Y-%m-%d")
            except: raise HTTPException(422,"Selecciona fecha de vencimiento.")
            c.execute("INSERT INTO obligations(name,scope,amount,due_date) VALUES(%s,%s,%s,%s) RETURNING id",(name,valid_scope(d.get("scope")),valid_amount(d.get("amount")),due))
        elif table=="budgets":
            name=str(d.get("name") or "").strip(); cat=str(d.get("category") or "").strip()
            if not name or not cat: raise HTTPException(422,"Completa nombre y categoría.")
            c.execute("INSERT INTO budgets(name,scope,category,monthly_limit) VALUES(%s,%s,%s,%s) RETURNING id",(name,valid_scope(d.get("scope")),cat,valid_amount(d.get("monthly_limit"))))
        else: raise HTTPException(404,"Sección inválida.")
        return {"id":c.fetchone()["id"],"ok":True}

@app.post("/api/obligations/{oid}/paid")
def paid(oid:int,user=Depends(auth)):
    with con() as c:
        c.execute("UPDATE obligations SET paid=1 WHERE id=%s RETURNING id",(oid,))
        if not c.fetchone(): raise HTTPException(404,"Obligación no encontrada.")
    return {"ok":True}

@app.get("/api/dashboard")
def dashboard(user=Depends(auth)):
    month=date.today().strftime("%Y-%m")
    with con() as c:
        def total(sql,args=()):
            c.execute(sql,args); return float(c.fetchone()["v"] or 0)
        return {
        "cash":total("SELECT COALESCE(SUM(balance),0) v FROM accounts WHERE scope='personal'"),
        "business_cash":total("SELECT COALESCE(SUM(balance),0) v FROM accounts WHERE scope='business'"),
        "debt":total("SELECT COALESCE(SUM(balance),0) v FROM debts WHERE scope='personal'"),
        "business_debt":total("SELECT COALESCE(SUM(balance),0) v FROM debts WHERE scope='business'"),
        "income":total("SELECT COALESCE(SUM(amount),0) v FROM movements WHERE ((kind='income' AND scope='personal') OR kind='withdrawal') AND substring(day,1,7)=%s",(month,)),
        "expense":total("SELECT COALESCE(SUM(amount),0) v FROM movements WHERE kind='expense' AND scope='personal' AND substring(day,1,7)=%s",(month,)),
        "business_income":total("SELECT COALESCE(SUM(amount),0) v FROM movements WHERE kind='income' AND scope='business' AND substring(day,1,7)=%s",(month,)),
        "business_expense":total("SELECT COALESCE(SUM(amount),0) v FROM movements WHERE kind='expense' AND scope='business' AND substring(day,1,7)=%s",(month,)),
        "obligations":total("SELECT COUNT(*) v FROM obligations WHERE paid=0"),
        "overdue":total("SELECT COUNT(*) v FROM obligations WHERE paid=0 AND due_date<%s",(date.today().isoformat(),))
        }

@app.post("/api/travis")
def travis(x:Data,user=Depends(auth)):
    d=dashboard(user); surplus=d["income"]-d["expense"]; advice=[]
    if d["overdue"]: advice.append("Tienes "+str(int(d["overdue"]))+" obligación(es) vencida(s): atiéndelas o negocia antes de abonar extra a deudas.")
    if d["obligations"]: advice.append("Separa primero el dinero de tus "+str(int(d["obligations"]))+" obligación(es) pendientes.")
    if surplus<0: advice.append("Tu gasto supera tu ingreso personal en $"+format(abs(surplus),",.2f")+" MXN. Revisa gastos variables y pausa los no esenciales.")
    elif surplus>0: advice.append("Tu flujo personal es positivo por $"+format(surplus,",.2f")+" MXN. Reserva vencimientos y liquidez antes de acelerar deudas.")
    if d["debt"] and d["cash"]<d["debt"]: advice.append("Tu deuda personal supera tu efectivo personal. Protege liquidez y pagos mínimos; después prioriza la tasa más alta.")
    elif d["debt"]: advice.append("Ordena tus deudas por tasa anual; cubre mínimos y dirige excedentes a la tasa más alta.")
    if not advice: advice.append("Faltan registros para un diagnóstico confiable. Captura saldos iniciales, movimientos, deudas y vencimientos.")
    q=str(x.data.get("question") or "").strip()[:800]
    answer=("TRAVIS · ANÁLISIS FINANCIERO\n\n"
    +"Efectivo personal: $"+format(d["cash"],",.2f")+" MXN\n"
    +"Deuda personal: $"+format(d["debt"],",.2f")+" MXN\n"
    +"Ingreso personal del mes: $"+format(d["income"],",.2f")+" MXN\n"
    +"Gasto personal del mes: $"+format(d["expense"],",.2f")+" MXN\n"
    +"Efectivo separado en negocios: $"+format(d["business_cash"],",.2f")+" MXN\n"
    +"Flujo personal: $"+format(surplus,",.2f")+" MXN\n\n"
    +"RECOMENDACIONES:\n- "+"\n- ".join(advice)
    +"\n\nLas transferencias internas no son ingresos. Los retiros de negocio a cuenta personal sí son ingreso personal y reducen el saldo del negocio. No ejecuto pagos ni transferencias.")
    if q: answer+="\n\nTu pregunta: "+q+"\nMi recomendación se basa en los registros disponibles; no inventaré datos faltantes."
    return {"answer":answer,"mode":"análisis financiero basado en reglas y datos registrados"}

@app.get("/api/export")
def export(user=Depends(auth)): return get_data(user)
