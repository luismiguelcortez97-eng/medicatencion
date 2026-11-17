import os, hmac, hashlib, secrets, json, urllib.request, urllib.error, calendar
from datetime import datetime, timedelta, date
from zoneinfo import ZoneInfo
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

# Todas las fechas operativas usan la hora local de Mexicali.
MEXICALI_TZ = ZoneInfo("America/Tijuana")
def mx_today():
    return datetime.now(MEXICALI_TZ).date()
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
    """CREATE TABLE IF NOT EXISTS budgets(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL,scope TEXT NOT NULL,category TEXT NOT NULL,monthly_limit DOUBLE PRECISION NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS assets(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL,scope TEXT NOT NULL,business_id BIGINT REFERENCES businesses(id),category TEXT NOT NULL,current_value DOUBLE PRECISION NOT NULL CHECK(current_value>=0))""",
    """CREATE TABLE IF NOT EXISTS financial_settings(id INTEGER PRIMARY KEY CHECK(id=1),emergency_months INTEGER NOT NULL DEFAULT 3 CHECK(emergency_months BETWEEN 1 AND 12))""",
    """ALTER TABLE accounts ADD COLUMN IF NOT EXISTS is_reserve BOOLEAN NOT NULL DEFAULT FALSE""",
    """ALTER TABLE debts ADD COLUMN IF NOT EXISTS due_type TEXT NOT NULL DEFAULT 'monthly_day'""",
    """ALTER TABLE debts ADD COLUMN IF NOT EXISTS due_date DATE""",
    """ALTER TABLE debts ADD COLUMN IF NOT EXISTS weekly_day INTEGER""",
    """ALTER TABLE obligations ADD COLUMN IF NOT EXISTS frequency TEXT NOT NULL DEFAULT 'once'"""
    ]
    with con() as c:
        for s in sqls: c.execute(s)
        c.execute("INSERT INTO financial_settings(id,emergency_months) VALUES(1,3) ON CONFLICT(id) DO NOTHING")
init_db()

def auth(authorization: str | None = Header(default=None)):
    try:
        if not authorization or not authorization.startswith("Bearer "): raise ValueError()
        payload, sig = authorization[7:].rsplit(".", 1)
        u, exp = payload.rsplit(":", 1)
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
    password: str = Field(min_length=6,max_length=200)
class Recovery(BaseModel):
    recovery_key: str = Field(min_length=32, max_length=256)
    new_username: str = Field(default="DOC", min_length=3, max_length=60, pattern=r"^[\w.-]+$")
    new_password: str = Field(min_length=6, max_length=200)

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
@app.post("/api/recover")
def recover_owner(x:Recovery):
    recovery_key=os.getenv("OWNER_RECOVERY_KEY")
    if not recovery_key or len(recovery_key)<32:
        raise HTTPException(503,"La recuperación no está habilitada.")
    if not hmac.compare_digest(x.recovery_key,recovery_key):
        raise HTTPException(403,"Clave de recuperación incorrecta.")
    salt=secrets.token_hex(16)
    hashed=hashlib.pbkdf2_hmac("sha256",x.new_password.encode(),bytes.fromhex(salt),310000).hex()
    with con() as c:
        c.execute("SELECT id FROM users ORDER BY id LIMIT 1 FOR UPDATE")
        owner=c.fetchone()
        if not owner: raise HTTPException(404,"No existe una cuenta propietaria para recuperar.")
        c.execute("UPDATE users SET username=%s,salt=%s,hash=%s WHERE id=%s",(x.new_username,salt,hashed,owner["id"]))
    return {"ok":True,"message":"Contraseña del propietario actualizada. Los registros se conservaron."}

@app.get("/api/data")
def get_data(user=Depends(auth)):
    with con() as c:
        out={}
        for t in ("businesses","accounts","movements","debts","obligations","budgets","assets"):
            c.execute("SELECT * FROM "+t+" ORDER BY id DESC"); out[t]=c.fetchall()
        return out

@app.post("/api/{table}")
def add(table:str,x:Data,user=Depends(auth)):
    d=x.data
    # /api/travis coincide con esta ruta dinámica; enrutarlo explícitamente al asistente.
    if table=="travis": return travis(x,user)
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
            c.execute("INSERT INTO accounts(name,kind,scope,business_id,balance,is_reserve) VALUES(%s,%s,%s,%s,%s,%s) RETURNING id",(name,d.get("kind") or "bank",sc,bid,bal,bool(d.get("is_reserve",False))))
        elif table=="movements":
            sc=valid_scope(d.get("scope")); n=valid_amount(d.get("amount")); k=d.get("kind")
            if k not in ("income","expense","transfer","withdrawal"): raise HTTPException(422,"Tipo de movimiento inválido.")
            day=str(d.get("day") or mx_today().isoformat())
            try: datetime.strptime(day,"%Y-%m-%d")
            except: raise HTTPException(422,"Fecha inválida.")
            bid=d.get("business_id") if sc=="business" or k=="withdrawal" else None
            if sc=="business" or k=="withdrawal":
                c.execute("SELECT id FROM businesses WHERE id=%s",(bid,))
                if not c.fetchone(): raise HTTPException(422,"Selecciona el negocio correspondiente.")
            item={"kind":k,"scope":sc,"amount":n,"account_id":d.get("account_id"),"dest_id":d.get("dest_id"),"business_id":bid}
            apply_movement(c,item)
            c.execute("INSERT INTO movements(kind,scope,concept,amount,day,account_id,dest_id,business_id,category) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (k,sc,str(d.get("concept") or "Sin concepto").strip(),n,day,item["account_id"],item["dest_id"],item["business_id"],d.get("category") or "General"))
        elif table=="assets":
            name=str(d.get("name") or "").strip(); sc=valid_scope(d.get("scope")); category=str(d.get("category") or "Otro").strip(); value=float(d.get("current_value") or 0)
            if not name or value<0 or value>1000000000: raise HTTPException(422,"Revisa el nombre y valor del activo.")
            bid=d.get("business_id") if sc=="business" else None
            if sc=="business":
                c.execute("SELECT id FROM businesses WHERE id=%s",(bid,))
                if not c.fetchone(): raise HTTPException(422,"Registra primero el negocio.")
            c.execute("INSERT INTO assets(name,scope,business_id,category,current_value) VALUES(%s,%s,%s,%s,%s) RETURNING id",(name,sc,bid,category,value))
        elif table=="debts":
            creditor=str(d.get("creditor") or "").strip()
            if not creditor: raise HTTPException(422,"Escribe el acreedor.")
            sc=valid_scope(d.get("scope")); n=valid_amount(d.get("balance")); rate=max(0,float(d.get("rate") or 0)); minimum=max(0,float(d.get("min_payment") or 0))
            due_type=str(d.get("due_type") or "date")
            due_date=d.get("due_date") or None
            weekly_day=d.get("weekly_day")
            due=None
            if due_type=="date":
                if not due_date: raise HTTPException(422,"Selecciona la fecha exacta de pago en el calendario.")
                try: datetime.strptime(str(due_date),"%Y-%m-%d")
                except ValueError: raise HTTPException(422,"La fecha de pago no es válida.")
            elif due_type=="weekly":
                try: weekly_day=int(weekly_day)
                except (TypeError,ValueError): raise HTTPException(422,"Selecciona el día semanal de pago.")
                if weekly_day not in range(7): raise HTTPException(422,"El día semanal no es válido.")
            elif due_type=="monthly_day":
                due=d.get("due_day")
                if due is None or not 1<=int(due)<=31: raise HTTPException(422,"Selecciona el día mensual de pago.")
                due=int(due)
            else: raise HTTPException(422,"Selecciona una modalidad de pago válida.")
            c.execute("INSERT INTO debts(creditor,scope,business_id,balance,rate,min_payment,due_day,due_type,due_date,weekly_day) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",(creditor,sc,d.get("business_id") if sc=="business" else None,n,rate,minimum,due,due_type,due_date,weekly_day))
        elif table=="obligations":
            name=str(d.get("name") or "").strip(); due=str(d.get("due_date") or "")
            frequency=str(d.get("frequency") or "once")
            if not name: raise HTTPException(422,"Escribe la obligación.")
            try: datetime.strptime(due,"%Y-%m-%d")
            except ValueError: raise HTTPException(422,"Selecciona la primera fecha de vencimiento.")
            if frequency not in ("once","weekly","monthly"): raise HTTPException(422,"Selecciona una frecuencia válida.")
            c.execute("INSERT INTO obligations(name,scope,amount,due_date,frequency) VALUES(%s,%s,%s,%s,%s) RETURNING id",(name,valid_scope(d.get("scope")),valid_amount(d.get("amount")),due,frequency))
        elif table=="budgets":
            name=str(d.get("name") or "").strip(); cat=str(d.get("category") or "").strip()
            if not name or not cat: raise HTTPException(422,"Completa nombre y categoría.")
            c.execute("INSERT INTO budgets(name,scope,category,monthly_limit) VALUES(%s,%s,%s,%s) RETURNING id",(name,valid_scope(d.get("scope")),cat,valid_amount(d.get("monthly_limit"))))
        else: raise HTTPException(404,"Sección inválida.")
        return {"id":c.fetchone()["id"],"ok":True}

def reverse_movement(c,item):
    k=item["kind"]; n=float(item["amount"]); src=item.get("account_id"); dst=item.get("dest_id")
    ids=[x for x in (src,dst) if x]
    if ids:
        c.execute("SELECT id,balance FROM accounts WHERE id = ANY(%s) FOR UPDATE",(ids,))
        balances={r["id"]:float(r["balance"]) for r in c.fetchall()}
    else: balances={}
    if k=="income":
        if not dst or dst not in balances: raise HTTPException(409,"La cuenta que recibió el ingreso ya no existe.")
        if balances[dst]+1e-8<n: raise HTTPException(409,"No se puede revertir el ingreso porque ese dinero ya fue utilizado. Ajusta primero el saldo de la cuenta.")
        c.execute("UPDATE accounts SET balance=balance-%s WHERE id=%s",(n,dst))
    elif k=="expense":
        if not src or src not in balances: raise HTTPException(409,"La cuenta del gasto ya no existe.")
        c.execute("UPDATE accounts SET balance=balance+%s WHERE id=%s",(n,src))
    elif k in ("transfer","withdrawal"):
        if not src or not dst or src not in balances or dst not in balances: raise HTTPException(409,"No se encontraron las cuentas del movimiento.")
        if balances[dst]+1e-8<n: raise HTTPException(409,"No se puede revertir el movimiento porque el dinero de destino ya fue utilizado.")
        c.execute("UPDATE accounts SET balance=balance+%s WHERE id=%s",(n,src))
        c.execute("UPDATE accounts SET balance=balance-%s WHERE id=%s",(n,dst))
    else: raise HTTPException(422,"Tipo de movimiento inválido.")

def movement_payload(d):
    sc=valid_scope(d.get("scope")); k=str(d.get("kind") or "")
    if k not in ("income","expense","transfer","withdrawal"): raise HTTPException(422,"Tipo de movimiento inválido.")
    amount=valid_amount(d.get("amount"))
    day=str(d.get("day") or mx_today().isoformat())
    try: datetime.strptime(day,"%Y-%m-%d")
    except ValueError: raise HTTPException(422,"Fecha inválida.")
    bid=d.get("business_id") if sc=="business" or k=="withdrawal" else None
    return {"kind":k,"scope":sc,"amount":amount,"day":day,"concept":str(d.get("concept") or "Sin concepto").strip(),"account_id":d.get("account_id"),"dest_id":d.get("dest_id"),"business_id":bid,"category":d.get("category") or "General"}

@app.put("/api/accounts/{account_id}")
def update_account(account_id:int,x:Data,user=Depends(auth)):
    d=x.data
    name=str(d.get("name") or "").strip()
    kind=str(d.get("kind") or "bank")
    if not name: raise HTTPException(422,"Escribe el nombre de la cuenta.")
    if kind not in ("bank","cash","savings","credit"): raise HTTPException(422,"Tipo de cuenta inválido.")
    with con() as c:
        c.execute("SELECT * FROM accounts WHERE id=%s FOR UPDATE",(account_id,))
        old=c.fetchone()
        if not old: raise HTTPException(404,"Cuenta no encontrada.")
        # El saldo puede corregirse manualmente; los movimientos históricos permanecen intactos.
        try: balance=float(d.get("balance",old["balance"]))
        except (TypeError,ValueError): raise HTTPException(422,"El efectivo debe ser una cantidad válida.")
        if not 0 <= balance <= 1000000000: raise HTTPException(422,"El saldo debe estar entre $0 y $1,000,000,000.")
        c.execute("UPDATE accounts SET name=%s,kind=%s,is_reserve=%s,balance=%s WHERE id=%s",
          (name,kind,bool(d.get("is_reserve",False)),balance,account_id))
    return {"ok":True,"id":account_id}

@app.delete("/api/accounts/{account_id}")
def delete_account(account_id:int,user=Depends(auth)):
    with con() as c:
        c.execute("SELECT * FROM accounts WHERE id=%s FOR UPDATE",(account_id,))
        account=c.fetchone()
        if not account: raise HTTPException(404,"Cuenta no encontrada.")
        c.execute("SELECT COUNT(*) AS n FROM movements WHERE account_id=%s OR dest_id=%s",(account_id,account_id))
        related=int(c.fetchone()["n"])
        if related:
            raise HTTPException(409,"No se puede eliminar: esta cuenta tiene movimientos históricos. Primero elimina o reasigna esos movimientos.")
        if abs(float(account["balance"] or 0))>0.005:
            raise HTTPException(409,"No se puede eliminar una cuenta con saldo. Deja su saldo en cero antes de eliminarla.")
        c.execute("DELETE FROM accounts WHERE id=%s",(account_id,))
    return {"ok":True,"id":account_id}

@app.put("/api/movements/{movement_id}")
def update_movement(movement_id:int,x:Data,user=Depends(auth)):
    item=movement_payload(x.data)
    with con() as c:
        c.execute("SELECT * FROM movements WHERE id=%s FOR UPDATE",(movement_id,))
        old=c.fetchone()
        if not old: raise HTTPException(404,"Movimiento no encontrado.")
        reverse_movement(c,old)
        apply_movement(c,item)
        c.execute("UPDATE movements SET kind=%s,scope=%s,concept=%s,amount=%s,day=%s,account_id=%s,dest_id=%s,business_id=%s,category=%s WHERE id=%s",
          (item["kind"],item["scope"],item["concept"],item["amount"],item["day"],item["account_id"],item["dest_id"],item["business_id"],item["category"],movement_id))
    return {"ok":True,"id":movement_id}

@app.delete("/api/movements/{movement_id}")
def delete_movement(movement_id:int,user=Depends(auth)):
    with con() as c:
        c.execute("SELECT * FROM movements WHERE id=%s FOR UPDATE",(movement_id,))
        old=c.fetchone()
        if not old: raise HTTPException(404,"Movimiento no encontrado.")
        reverse_movement(c,old)
        c.execute("DELETE FROM movements WHERE id=%s",(movement_id,))
    return {"ok":True,"id":movement_id}

@app.put("/api/debts/{debt_id}")
def update_debt(debt_id:int,x:Data,user=Depends(auth)):
    d=x.data
    creditor=str(d.get("creditor") or "").strip()
    if not creditor: raise HTTPException(422,"Escribe el acreedor.")
    sc=valid_scope(d.get("scope"))
    balance=valid_amount(d.get("balance"))
    try:
        rate=float(d.get("rate") or 0)
        minimum=float(d.get("min_payment") or 0)
    except (TypeError,ValueError):
        raise HTTPException(422,"Revisa tasa y pago mínimo.")
    if not 0<=rate<=10000 or not 0<=minimum<=1000000000:
        raise HTTPException(422,"La tasa o el pago mínimo no son válidos.")
    due_type=str(d.get("due_type") or "date")
    due_date=d.get("due_date") or None
    weekly_day=d.get("weekly_day")
    due=None
    if due_type=="date":
        if not due_date: raise HTTPException(422,"Selecciona la fecha exacta de pago en el calendario.")
        try: datetime.strptime(str(due_date),"%Y-%m-%d")
        except ValueError: raise HTTPException(422,"La fecha de pago no es válida.")
    elif due_type=="weekly":
        try: weekly_day=int(weekly_day)
        except (TypeError,ValueError): raise HTTPException(422,"Selecciona el día semanal de pago.")
        if weekly_day not in range(7): raise HTTPException(422,"El día semanal no es válido.")
    elif due_type=="monthly_day":
        try: due=int(d["due_day"])
        except (TypeError,ValueError,KeyError): raise HTTPException(422,"Selecciona el día mensual de pago.")
        if not 1<=due<=31: raise HTTPException(422,"Día de pago entre 1 y 31.")
    else: raise HTTPException(422,"Selecciona una modalidad de pago válida.")
    bid=d.get("business_id") if sc=="business" else None
    with con() as c:
        if sc=="business":
            c.execute("SELECT id FROM businesses WHERE id=%s",(bid,))
            if not c.fetchone(): raise HTTPException(422,"Selecciona un negocio válido.")
        c.execute("UPDATE debts SET creditor=%s,scope=%s,business_id=%s,balance=%s,rate=%s,min_payment=%s,due_day=%s,due_type=%s,due_date=%s,weekly_day=%s WHERE id=%s RETURNING id",
            (creditor,sc,bid,balance,rate,minimum,due,due_type,due_date,weekly_day,debt_id))
        if not c.fetchone(): raise HTTPException(404,"No se encontró esa deuda.")
    return {"ok":True,"id":debt_id}

@app.post("/api/settings/emergency-fund")
def update_emergency_settings(x:Data,user=Depends(auth)):
    try: months=int(x.data.get("target_months",3))
    except (TypeError,ValueError): raise HTTPException(422,"Selecciona entre 1 y 12 meses.")
    if months<1 or months>12: raise HTTPException(422,"El objetivo debe estar entre 1 y 12 meses.")
    with con() as c: c.execute("INSERT INTO financial_settings(id,emergency_months) VALUES(1,%s) ON CONFLICT(id) DO UPDATE SET emergency_months=EXCLUDED.emergency_months",(months,))
    return {"ok":True,"target_months":months}

@app.post("/api/obligations/{oid}/paid")
def paid(oid:int,user=Depends(auth)):
    with con() as c:
        c.execute("SELECT id,due_date,frequency FROM obligations WHERE id=%s FOR UPDATE",(oid,))
        row=c.fetchone()
        if not row: raise HTTPException(404,"Obligación no encontrada.")
        frequency=row.get("frequency") or "once"
        if frequency=="weekly":
            next_due=(date.fromisoformat(str(row["due_date"])[:10])+timedelta(days=7)).isoformat()
            c.execute("UPDATE obligations SET due_date=%s,paid=0 WHERE id=%s",(next_due,oid))
        elif frequency=="monthly":
            current=date.fromisoformat(str(row["due_date"])[:10])
            year=current.year+(1 if current.month==12 else 0)
            month=1 if current.month==12 else current.month+1
            next_due=date(year,month,min(current.day,calendar.monthrange(year,month)[1])).isoformat()
            c.execute("UPDATE obligations SET due_date=%s,paid=0 WHERE id=%s",(next_due,oid))
        else:
            c.execute("UPDATE obligations SET paid=1 WHERE id=%s",(oid,))
    return {"ok":True,"next_due":next_due if frequency in ("weekly","monthly") else None}

@app.get("/api/dashboard")
def dashboard(user=Depends(auth)):
    month=mx_today().strftime("%Y-%m")
    with con() as c:
        def total(sql,args=()):
            c.execute(sql,args); return float(c.fetchone()["v"] or 0)
        c.execute("SELECT emergency_months FROM financial_settings WHERE id=1"); setting=c.fetchone()
        emergency_months=int(setting["emergency_months"]) if setting else 3
        reserve=total("SELECT COALESCE(SUM(balance),0) v FROM accounts WHERE scope='personal' AND is_reserve=TRUE")
        monthly_expense_avg=total("SELECT COALESCE(SUM(amount),0)/3.0 v FROM movements WHERE kind='expense' AND scope='personal' AND day >= %s",( (mx_today()-timedelta(days=90)).isoformat(), ))
        personal_assets=total("SELECT COALESCE(SUM(current_value),0) v FROM assets WHERE scope='personal'")
        business_assets=total("SELECT COALESCE(SUM(current_value),0) v FROM assets WHERE scope='business'")
        return {
        "emergency_months":emergency_months,
        "emergency_fund_balance":reserve,
        "emergency_monthly_expense_avg":monthly_expense_avg,
        "emergency_fund_target":monthly_expense_avg*emergency_months,
        "personal_assets":personal_assets,
        "business_assets":business_assets,
        "personal_net_worth":total("SELECT COALESCE(SUM(balance),0) v FROM accounts WHERE scope='personal'")+personal_assets-total("SELECT COALESCE(SUM(balance),0) v FROM debts WHERE scope='personal'"),
        "business_net_worth":total("SELECT COALESCE(SUM(balance),0) v FROM accounts WHERE scope='business'")+business_assets-total("SELECT COALESCE(SUM(balance),0) v FROM debts WHERE scope='business'"),
        "net_worth":total("SELECT COALESCE(SUM(balance),0) v FROM accounts")+personal_assets+business_assets-total("SELECT COALESCE(SUM(balance),0) v FROM debts"),
        "cash":total("SELECT COALESCE(SUM(balance),0) v FROM accounts WHERE scope='personal'"),
        "business_cash":total("SELECT COALESCE(SUM(balance),0) v FROM accounts WHERE scope='business'"),
        "debt":total("SELECT COALESCE(SUM(balance),0) v FROM debts WHERE scope='personal'"),
        "business_debt":total("SELECT COALESCE(SUM(balance),0) v FROM debts WHERE scope='business'"),
        "income":total("SELECT COALESCE(SUM(amount),0) v FROM movements WHERE ((kind='income' AND scope='personal') OR kind='withdrawal') AND substring(day,1,7)=%s",(month,)),
        "expense":total("SELECT COALESCE(SUM(amount),0) v FROM movements WHERE kind='expense' AND scope='personal' AND substring(day,1,7)=%s",(month,)),
        "business_income":total("SELECT COALESCE(SUM(amount),0) v FROM movements WHERE kind='income' AND scope='business' AND substring(day,1,7)=%s",(month,)),
        "business_expense":total("SELECT COALESCE(SUM(amount),0) v FROM movements WHERE kind='expense' AND scope='business' AND substring(day,1,7)=%s",(month,)),
        "obligations":total("SELECT COUNT(*) v FROM obligations WHERE paid=0"),
        "overdue":total("SELECT COUNT(*) v FROM obligations WHERE paid=0 AND due_date<%s",(mx_today().isoformat(),))
        }

@app.get("/api/insights")
def insights(user=Depends(auth)):
    today=mx_today()
    start=(today-timedelta(days=90)).isoformat()
    month=today.strftime("%Y-%m")
    with con() as c:
        def total(sql,args=()):
            c.execute(sql,args)
            return float(c.fetchone()["v"] or 0)
        avg_income=total("SELECT COALESCE(SUM(amount),0)/3.0 v FROM movements WHERE ((kind='income' AND scope='personal') OR kind='withdrawal') AND day >= %s",(start,))
        avg_expense=total("SELECT COALESCE(SUM(amount),0)/3.0 v FROM movements WHERE kind='expense' AND scope='personal' AND day >= %s",(start,))
        monthly_surplus=avg_income-avg_expense
        cash=total("SELECT COALESCE(SUM(balance),0) v FROM accounts WHERE scope='personal'")
        reserve=total("SELECT COALESCE(SUM(balance),0) v FROM accounts WHERE scope='personal' AND is_reserve=TRUE")
        target_months=total("SELECT emergency_months v FROM financial_settings WHERE id=1")
        target=avg_expense*int(target_months or 3)
        c.execute("SELECT creditor,balance,rate,min_payment,due_day FROM debts WHERE scope='personal' AND balance>0 ORDER BY rate DESC,balance DESC")
        debts=c.fetchall()
        c.execute("SELECT b.id,b.name,b.category,b.scope,b.monthly_limit,COALESCE(SUM(m.amount),0) spent FROM budgets b LEFT JOIN movements m ON m.scope=b.scope AND m.category=b.category AND m.kind='expense' AND substring(m.day,1,7)=%s GROUP BY b.id ORDER BY b.scope,b.name",(month,))
        budgets=c.fetchall()
        gap=max(0,target-reserve)
        if monthly_surplus>0:
            if gap>0:
                allocation={"fondo_emergencia":round(min(monthly_surplus*0.5,gap),2),"deuda_prioritaria":round(monthly_surplus*0.4,2),"margen_libre":round(monthly_surplus*0.1,2)}
            else:
                allocation={"fondo_emergencia":0,"deuda_prioritaria":round(monthly_surplus*0.7,2),"ahorro_objetivos":round(monthly_surplus*0.2,2),"margen_libre":round(monthly_surplus*0.1,2)}
        else:
            allocation={"fondo_emergencia":0,"deuda_prioritaria":0,"margen_libre":0}
        projections=[]
        for months in (3,6,12,24):
            projections.append({"months":months,"projected_cash":round(cash+monthly_surplus*months,2)})
        return {
            "period_days":90,"average_monthly_income":round(avg_income,2),
            "average_monthly_expense":round(avg_expense,2),"average_monthly_surplus":round(monthly_surplus,2),
            "emergency_target":round(target,2),"emergency_gap":round(gap,2),
            "allocation":allocation,"debt_priority":debts,
            "budgets":[{**b,"spent":float(b["spent"] or 0),"usage_pct":round(float(b["spent"] or 0)/float(b["monthly_limit"])*100,1) if b["monthly_limit"] else 0} for b in budgets],
            "projections":projections,
            "projection_note":"Estimación lineal con el promedio de los últimos 90 días; no es una garantía ni incorpora cambios futuros."
        }


def _next_debt_due(row, today):
    kind=row.get("due_type") or "monthly_day"
    if kind=="date" and row.get("due_date"):
        due=date.fromisoformat(str(row["due_date"])[:10])
        return due
    if kind=="weekly" and row.get("weekly_day") is not None:
        target=int(row["weekly_day"])
        return today+timedelta(days=(target-today.weekday())%7)
    if row.get("due_day"):
        day=int(row["due_day"])
        candidate=date(today.year,today.month,min(day,calendar.monthrange(today.year,today.month)[1]))
        if candidate<today:
            if today.month==12: year,month=today.year+1,1
            else: year,month=today.year,today.month+1
            candidate=date(year,month,min(day,calendar.monthrange(year,month)[1]))
        return candidate
    return None

@app.get("/api/decision-plan")
def decision_plan(user=Depends(auth)):
    today=mx_today()
    horizon7=today+timedelta(days=7)
    horizon30=today+timedelta(days=30)
    with con() as c:
        c.execute("SELECT id,name,scope,business_id,balance,is_reserve FROM accounts ORDER BY scope,id")
        accounts=c.fetchall()
        c.execute("SELECT id,name,scope,amount,due_date,frequency,paid FROM obligations WHERE paid=0 ORDER BY due_date")
        obligations=c.fetchall()
        c.execute("SELECT id,creditor,scope,business_id,balance,rate,min_payment,due_type,due_date,weekly_day,due_day FROM debts WHERE balance>0 ORDER BY rate DESC")
        debts=c.fetchall()
        c.execute("SELECT id,name FROM businesses ORDER BY name")
        businesses=c.fetchall()
        c.execute("SELECT kind,scope,amount,day,business_id,category FROM movements WHERE day >= %s AND kind IN ('income','expense')",( (today-timedelta(days=90)).isoformat(), ))
        movements=c.fetchall()
    cash_personal=sum(float(a["balance"] or 0) for a in accounts if a["scope"]=="personal" and not a["is_reserve"])
    reserve=sum(float(a["balance"] or 0) for a in accounts if a["scope"]=="personal" and a["is_reserve"])
    cash_business={}
    for b in businesses:
        cash_business[b["id"]]=sum(float(a["balance"] or 0) for a in accounts if a["scope"]=="business" and a["business_id"]==b["id"])
    due_items=[]
    monthly_obligations={"personal":0.0,"business":0.0}
    weekly_obligations={"personal":0.0,"business":0.0}
    monthly_debt_minimums={"personal":0.0,"business":0.0}
    weekly_debt_minimums={"personal":0.0,"business":0.0}
    one_time_due_this_month={"personal":0.0,"business":0.0}
    month_start=date(today.year,today.month,1)
    month_end=date(today.year+(1 if today.month==12 else 0),1 if today.month==12 else today.month+1,1)-timedelta(days=1)
    for o in obligations:
        try: due=date.fromisoformat(str(o["due_date"])[:10])
        except Exception: continue
        amount=float(o["amount"] or 0)
        scope=o["scope"] if o["scope"] in ("personal","business") else "personal"
        frequency=(o.get("frequency") or "once").lower()
        if frequency=="weekly":
            weekly_obligations[scope]+=amount
            monthly_obligations[scope]+=amount*52/12
        elif frequency=="monthly":
            monthly_obligations[scope]+=amount
        elif month_start<=due<=month_end:
            one_time_due_this_month[scope]+=amount
        due_items.append({"id":int(o["id"]),"type":"obligation","name":o["name"],"scope":scope,"amount":amount,"frequency":frequency,"monthly_equivalent":round(amount*52/12,2) if frequency=="weekly" else (amount if frequency=="monthly" else (amount if month_start<=due<=month_end else 0)),"due":due.isoformat(),"days":(due-today).days,"business_id":None})
    for d in debts:
        due=_next_debt_due(d,today)
        amount=float(d["min_payment"] or 0)
        scope=d["scope"] if d["scope"] in ("personal","business") else "personal"
        due_type=(d.get("due_type") or "monthly_day").lower()
        if due_type=="weekly":
            weekly_debt_minimums[scope]+=amount
            monthly_debt_minimums[scope]+=amount*52/12
        elif due_type=="monthly_day":
            monthly_debt_minimums[scope]+=amount
        if due:
            due_items.append({"id":int(d["id"]),"type":"debt_minimum","name":d["creditor"],"scope":scope,"amount":amount,"frequency":"weekly" if due_type=="weekly" else "monthly" if due_type=="monthly_day" else "date","monthly_equivalent":round(amount*52/12,2) if due_type=="weekly" else (amount if due_type=="monthly_day" else 0),"due":due.isoformat(),"days":(due-today).days,"rate":float(d["rate"] or 0),"balance":float(d["balance"] or 0),"business_id":d["business_id"]})
    monthly_fixed_total={scope:round(monthly_obligations[scope]+monthly_debt_minimums[scope],2) for scope in ("personal","business")}
    monthly_cash_commitments={scope:round(monthly_fixed_total[scope]+one_time_due_this_month[scope],2) for scope in ("personal","business")}
    due7=[x for x in due_items if x["days"]<=7]
    due30=[x for x in due_items if x["days"]<=30]
    def totals(items,scope):
        return round(sum(x["amount"] for x in items if x["scope"]==scope),2)
    personal_due7=totals(due7,"personal")
    personal_due30=totals(due30,"personal")
    personal_free7=round(cash_personal-personal_due7,2)
    priorities=[]
    for item in sorted(due_items,key=lambda x:(x["days"],0 if x["type"]=="obligation" else 1,-x.get("rate",0))):
        if item["days"]<0: label="VENCIDO"
        elif item["days"]<=7: label="EN LOS PRÓXIMOS 7 DÍAS"
        elif item["days"]<=30: label="EN LOS PRÓXIMOS 30 DÍAS"
        else: continue
        priorities.append({**item,"status":label})
    by_business=[]
    for b in businesses:
        inc=sum(float(m["amount"] or 0) for m in movements if m["business_id"]==b["id"] and m["kind"]=="income")
        exp=sum(float(m["amount"] or 0) for m in movements if m["business_id"]==b["id"] and m["kind"]=="expense")
        by_business.append({"name":b["name"],"income_90d":round(inc,2),"expense_90d":round(exp,2),"operating_difference_90d":round(inc-exp,2),"cash":round(cash_business.get(b["id"],0),2)})
    expense_categories={}
    for m in movements:
        if m["kind"]=="expense":
            key=("Personal" if m["scope"]=="personal" else "Negocio")+" · "+str(m["category"] or "General")
            expense_categories[key]=expense_categories.get(key,0)+float(m["amount"] or 0)
    top_costs=sorted([{"category":k,"amount_90d":round(v,2)} for k,v in expense_categories.items()],key=lambda x:x["amount_90d"],reverse=True)[:8]
    movement_days=len(set(str(m["day"])[:10] for m in movements))
    if personal_free7<0:
        next_action="Tu efectivo personal no alcanza para cubrir todos los compromisos de los próximos 7 días. No adelantes deudas: prioriza vencidos y esenciales, confirma fechas y negocia antes del vencimiento."
    elif priorities:
        next_action="Aparta primero los compromisos personales que vencen en los próximos 7 días. Después cubre los mínimos de deuda; solo considera abonos extra con el sobrante confirmado."
    elif personal_free7>0:
        next_action="No aparecen compromisos personales registrados para los próximos 7 días. Conserva liquidez y revisa pagos de los siguientes 30 días antes de acelerar deudas."
    else:
        next_action="Registra fechas y pagos mínimos de tus deudas y obligaciones para calcular qué dinero está realmente libre."
    return {"as_of":today.isoformat(),"personal_cash_nonreserve":round(cash_personal,2),"personal_reserve":round(reserve,2),"personal_due_7d":personal_due7,"personal_due_30d":personal_due30,"personal_free_after_7d":personal_free7,"monthly_obligations_personal":round(monthly_obligations["personal"],2),"monthly_obligations_business":round(monthly_obligations["business"],2),"weekly_obligations_personal":round(weekly_obligations["personal"],2),"weekly_obligations_business":round(weekly_obligations["business"],2),"monthly_debt_minimums_personal":round(monthly_debt_minimums["personal"],2),"monthly_debt_minimums_business":round(monthly_debt_minimums["business"],2),"weekly_debt_minimums_personal":round(weekly_debt_minimums["personal"],2),"weekly_debt_minimums_business":round(weekly_debt_minimums["business"],2),"monthly_fixed_total_personal":monthly_fixed_total["personal"],"monthly_fixed_total_business":monthly_fixed_total["business"],"one_time_due_this_month_personal":round(one_time_due_this_month["personal"],2),"one_time_due_this_month_business":round(one_time_due_this_month["business"],2),"monthly_cash_commitments_personal":monthly_cash_commitments["personal"],"monthly_cash_commitments_business":monthly_cash_commitments["business"],"weekly_to_monthly_factor":round(52/12,4),"priorities":priorities[:20],"businesses":by_business,"largest_expense_categories_90d":top_costs,"movement_days_90d":movement_days,"has_90d_data":bool(movements),"next_action":next_action,"caveat":"Los pagos semanales se convierten a equivalente mensual usando 52/12 semanas por mes (4.333); las obligaciones de una sola vez se muestran aparte. Incluye pagos registrados y mínimos de deuda, pero no gastos esenciales no capturados. No dupliques una misma deuda como obligación."}

@app.post("/api/travis")
def travis(x:Data,user=Depends(auth)):
    question=str(x.data.get("question") or "").strip()[:3000]
    page=str(x.data.get("context") or "general")[:80]
    raw_history=x.data.get("history") or []
    history=[]
    if isinstance(raw_history,list):
        for item in raw_history[-12:]:
            if not isinstance(item,dict): continue
            role=item.get("role")
            content=str(item.get("content") or "").strip()[:3000]
            if role in ("user","assistant") and content:
                history.append({"role":role,"content":content})
    d=dashboard(user)
    ins=insights(user)
    # Estado operativo real: evita que Travis repita pasos ya completados.
    with con() as c:
        c.execute("SELECT id,name FROM businesses ORDER BY id")
        registered_businesses=c.fetchall()
        c.execute("SELECT id,name,kind,scope,business_id,balance FROM accounts ORDER BY id")
        registered_accounts=c.fetchall()
        c.execute("SELECT id,creditor,scope,balance,due_type,due_date,weekly_day,due_day FROM debts ORDER BY id")
        registered_debts=c.fetchall()
        c.execute("SELECT id,name,scope,amount,due_date,frequency,paid FROM obligations ORDER BY id")
        registered_obligations=c.fetchall()
        c.execute("SELECT id,name,scope,category,monthly_limit FROM budgets ORDER BY id")
        registered_budgets=c.fetchall()
        c.execute("SELECT id,name,scope,category,current_value FROM assets ORDER BY id")
        registered_assets=c.fetchall()
        c.execute("SELECT COUNT(*) AS total FROM movements")
        movement_count=c.fetchone()["total"]
    records={
        "negocios_registrados":registered_businesses,
        "cuentas_registradas":registered_accounts,
        "deudas_registradas":registered_debts,
        "obligaciones_registradas":registered_obligations,
        "presupuestos_registrados":registered_budgets,
        "activos_registrados":registered_assets,
        "cantidad_movimientos_registrados":movement_count
    }
    plan=decision_plan(user)
    snapshot={
        "plan_de_accion_financiero":plan,
        "estado_real_de_registros":records,
        "moneda":"MXN",
        "efectivo_personal":d["cash"],
        "deuda_personal":d["debt"],
        "ingreso_personal_mes":d["income"],
        "gasto_personal_mes":d["expense"],
        "flujo_personal_mes":round(d["income"]-d["expense"],2),
        "efectivo_negocios_separado":d["business_cash"],
        "deuda_negocios_separada":d["business_debt"],
        "fondo_emergencia":d["emergency_fund_balance"],
        "objetivo_fondo_emergencia":d["emergency_fund_target"],
        "promedio_ingreso_90_dias":ins["average_monthly_income"],
        "promedio_gasto_90_dias":ins["average_monthly_expense"],
        "excedente_estimado":ins["average_monthly_surplus"],
        "brecha_fondo":ins["emergency_gap"],
        "distribucion_sugerida":ins["allocation"],
        "deudas_por_prioridad":ins["debt_priority"][:12],
        "presupuestos":ins["budgets"][:20],
        "obligaciones_vencidas":d["overdue"],
        "obligaciones_pendientes":d["obligations"]
    }
    # Travis usa Groq Free como proveedor principal. No llama a OpenAI para evitar cargos.
    key=os.getenv("GROQ_API_KEY")
    if key:
        model=os.getenv("GROQ_MODEL","openai/gpt-oss-120b")
        system=("Eres Travis, la IA personal del usuario dentro de Finanzas con Travis. Tu identidad es Travis. "
        "Habla como un asistente conversacional real, cálido, atento, natural y espontáneo, no como un formulario, buscador ni generador automático de reportes. "
        "Entiende el contexto y continúa la conversación usando los mensajes anteriores que recibes. Si el usuario te saluda, te presenta, te agradece, bromea o comenta algo personal, responde a ese acto conversacional directamente y con naturalidad; no conviertas todo en una consulta financiera. "
        "Por ejemplo, si dice 'Travis, te acabo de crear', responde agradeciendo la bienvenida, preséntate brevemente y dile que estás listo para ayudarle. No respondas con instrucciones técnicas ni con un análisis de sus finanzas salvo que te lo pida. "
        "No digas que careces de memoria cuando el historial de esta conversación está incluido. No inventes recuerdos que no aparezcan en el historial. "
        "Tu alcance no se limita a las finanzas: responde preguntas de ciencia, historia, cultura, tecnología, medicina general, programación, educación, negocios, matemáticas, idiomas y temas cotidianos. "
        "Contesta directamente y con profundidad proporcional a la pregunta. Explica conceptos desde cero cuando sea necesario, da ejemplos prácticos y adapta el nivel al usuario. "
        "No afirmes saberlo todo ni inventes datos. Si no tienes certeza, dilo claramente, distingue hechos de hipótesis y señala qué información falta. No inventes fuentes, citas, cifras, tasas, fechas ni capacidades. "
        "Tu conocimiento puede no incluir acontecimientos posteriores a tu entrenamiento: cuando una pregunta dependa de noticias, precios, leyes, horarios, versiones, estadísticas o datos recientes, advierte que necesitas una fuente actualizada; no presentes datos antiguos como actuales. "
        "ÁMBITO DE LA APLICACIÓN: conoces Finanzas con Travis y sus módulos: Inicio/Panel general, Cuentas y movimientos, Negocios, Deudas, Fondo de emergencia, Distribución, Presupuestos, Proyección, Reportes y Travis. Tu función principal es ayudar a decidir y resolver, no dar tutoriales. "
        "REGLA OBLIGATORIA AL ENSEÑAR EL PROGRAMA: responde únicamente con texto conversacional. No muestres, insertes, reproduzcas ni simules páginas de la aplicación, pantallas, interfaces, paneles, tarjetas, tablas, formularios, botones visuales, capturas, bloques de código ni enlaces para abrir secciones. No escribas como si estuvieras mostrando la página. Describe con palabras qué debe hacer el usuario dentro de la aplicación. "
        "ESTILO DE RESPUESTA PRIORITARIO: sé muy directo, breve y conversacional. Habla como una persona en un chat natural, con párrafos cortos y lenguaje cotidiano. No conviertas cada respuesta en una lista, esquema, reporte ni enumeración; evita numerar con 1, 2, 3 o usar viñetas por costumbre. Responde normalmente en una o dos frases fluidas, como parte de una conversación. Usa listas solo cuando el usuario las pida o cuando comparar varios importes, fechas o alternativas sea realmente más claro; incluso entonces, mantenlas cortas. No escribas introducciones largas, resúmenes de lo que vas a hacer, tutoriales, explicaciones desde cero ni repitas contexto en cada respuesta. No expliques cómo usar la aplicación salvo que el usuario pregunte cómo hacerlo o sea indispensable para completar una acción; en ese caso da únicamente la instrucción mínima necesaria, integrada naturalmente en la conversación. Si pregunta qué pagar, dile de forma natural qué concepto, cuánto y cuándo. Si pregunta qué hacer, recomienda la siguiente acción concreta. Si faltan datos, pregunta solo el dato indispensable en una frase natural. Amplía únicamente si el usuario pide detalles. "
        "REGLA PRIORITARIA DE PROGRESO: antes de recomendar o preguntar por cualquier paso de configuración, revisa siempre estado_real_de_registros dentro del contexto de la aplicación. Ese inventario proviene directamente de la base de datos y es la fuente de verdad. Si negocios_registrados contiene uno o más elementos, nunca preguntes si ya registró sus negocios ni le indiques registrarlos otra vez; reconoce los nombres existentes y continúa con el primer módulo posterior que realmente falte. Aplica lo mismo a cuentas, deudas, obligaciones, presupuestos y activos: no repitas tareas ya completadas. Si ya existen algunos registros pero faltan otros, menciona brevemente lo que ya está hecho y guía únicamente al siguiente paso pendiente. No confundas una lista vacía con un error de carga; si el estado no está disponible o es ambiguo, pregunta antes de afirmar que no hay registros. Si el usuario informa que acaba de completar un paso, el siguiente mensaje debe reconocerlo y verificar el estado actualizado antes de continuar. "
        "No afirmes que existe una función que no esté implementada. Si el usuario solo hace una pregunta casual o habla contigo, no inicies una explicación del programa. "
        "ÁMBITO FINANCIERO: cuando la pregunta sea financiera, actúa como asesor educativo riguroso y asesor de decisiones. Usa plan_de_accion_financiero para responder qué pagar primero, qué cantidad apartar, cuánto queda realmente libre y qué conviene hacer después. Cuando el usuario pregunte cuánto paga al mes o cuánto necesita apartar mensualmente, usa obligatoriamente monthly_fixed_total_personal y monthly_fixed_total_business del plan. Incluye obligaciones mensuales una vez y convierte cada pago semanal a equivalente mensual multiplicando por 52/12 (aprox. 4.33), nunca lo cuentes como si ocurriera solo una vez. Muestra por separado pagos semanales, pagos mensuales y compromisos extraordinarios de una sola vez; evita sumar dos veces una misma deuda registrada también como obligación. Si el usuario espera un presupuesto de cuatro semanas exactas, aclara la diferencia entre 4 semanas y el promedio mensual de 4.33 semanas. Prioriza compromisos vencidos y próximos 7 días, pagos mínimos, liquidez y protección de reservas; no recomiendes abonos extraordinarios si el efectivo libre calculado es negativo o si faltan gastos esenciales. Para acelerar deuda compara tasas/CAT y usa avalancha o bola de nieve según costo y motivación, explicando la diferencia. Para mejorar ingresos analiza diferencia operativa por negocio y categorías de gasto; nunca confundas ventas con utilidad ni sugieras crecer una actividad sin evidencia de margen. Aplica presupuesto base cero, capital de trabajo, fondo de emergencia, amortización, riesgo, inflación, interés compuesto, patrimonio neto y escenarios. Distingue educación general de recomendación personalizada; explica ventajas, riesgos, supuestos y datos faltantes. "
        "Analiza exclusivamente los datos entregados; si faltan datos dilo y pregunta solo lo indispensable. Responde en español mexicano, con prioridades concretas y cantidades en MXN cuando corresponda. Separa siempre finanzas personales y empresariales. Transferencias entre cuentas propias no son ingresos. Un retiro del negocio es ingreso personal pero no ingreso nuevo del negocio: reduce caja empresarial y aumenta la personal. "
        "No ordenes ni afirmes ejecutar pagos, transferencias o movimientos. No inventes tasas, CAT, fechas ni saldos. Considera liquidez, obligaciones vencidas, pagos mínimos, fondo de emergencia y riesgo. Explica supuestos y advierte cuando la muestra de 90 días sea insuficiente. "
        "No fuerces una respuesta financiera si la pregunta trata de otro tema. Para preguntas generales, responde como asistente general y no recites el estado financiero del usuario si no es pertinente. "
        "Estructura respuestas complejas con: respuesta o diagnóstico; explicación; pasos accionables; incertidumbres o datos faltantes. Mantén un tono claro, respetuoso, natural y útil.")
        messages=[{"role":"system","content":system},
        {"role":"system","content":"Contexto de la aplicación y datos financieros actuales (MXN). Úsalos solo si son pertinentes a la conversación; nunca los recites espontáneamente: "+json.dumps({"pestana_actual":page,"datos":snapshot},ensure_ascii=False,default=str)}]
        messages.extend(history)
        messages.append({"role":"user","content":question or "Analiza mi situación y dime las tres prioridades."})
        payload={"model":model,"messages":messages,"temperature":0.55,"max_tokens":900}
        try:
            req=urllib.request.Request("https://api.groq.com/openai/v1/chat/completions",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Authorization":"Bearer "+key,"Content-Type":"application/json","User-Agent":"FinanzasConTravis/1.0 (+https://finanzas-4l09.onrender.com)"},
                method="POST")
            with urllib.request.urlopen(req,timeout=35) as response:
                result=json.loads(response.read().decode("utf-8"))
            answer=result["choices"][0]["message"]["content"].strip()
            return {"answer":answer,"mode":"Groq Free · IA generativa","ai_enabled":True}
        except urllib.error.HTTPError as e:
            try:
                raw=e.read().decode("utf-8","replace")
            except Exception:
                raw=""
            try:
                parsed=json.loads(raw)
                err=parsed.get("error",{}) if isinstance(parsed,dict) else {}
                detail=err.get("message","") if isinstance(err,dict) else str(err)
                code=err.get("code","") if isinstance(err,dict) else ""
            except Exception:
                detail=raw
                code=""
            detail=(str(detail or e.reason or "Sin detalle del proveedor")).replace("\\n"," ")[:700]
            print("TRAVIS_GROQ_HTTP_ERROR",e.code,"CODE",code,"DETAIL",detail,flush=True)
            return {"answer":"Groq rechazó la solicitud (HTTP "+str(e.code)+"). "+detail,"mode":"error de conexión Groq","ai_enabled":False}
        except Exception as e:
            print("TRAVIS_GROQ_ERROR",type(e).__name__,str(e)[:500],flush=True)
            return {"answer":"No pude conectar con Groq en este momento ("+type(e).__name__+"). Intenta de nuevo en unos segundos.","mode":"error de conexión Groq","ai_enabled":False}
    advice=[]
    surplus=d["income"]-d["expense"]
    if d["overdue"]: advice.append("Prioridad 1: revisa las "+str(int(d["overdue"]))+" obligaciones vencidas y contacta al acreedor antes de destinar excedentes a pagos anticipados.")
    if surplus<0: advice.append("Prioridad 1: tu gasto personal del mes supera el ingreso registrado por "+format(abs(surplus),",.2f")+" MXN. Protege vivienda, alimentación, salud y servicios; identifica gastos que puedas pausar.")
    elif surplus>0: advice.append("Prioridad: tu flujo personal mensual es positivo en "+format(surplus,",.2f")+" MXN. Separa primero obligaciones y pagos mínimos; luego distribuye el excedente según el fondo y las tasas reales.")
    else: advice.append("Tu flujo mensual registrado está en equilibrio. Evita comprometer dinero que todavía no ha entrado.")
    if ins["emergency_gap"]>0: advice.append("Tu fondo de emergencia tiene una brecha estimada de "+format(ins["emergency_gap"],",.2f")+" MXN. Construye liquidez gradualmente sin dejar de cubrir pagos mínimos.")
    if ins["debt_priority"]: advice.append("Para acelerar deudas, después de cubrir mínimos, compara CAT/tasa efectiva y penalizaciones; el orden mostrado por tasa anual es orientativo.")
    answer=("TRAVIS · ANÁLISIS CON TUS REGISTROS\n\n"
    +"Efectivo personal: "+format(d["cash"],",.2f")+" MXN\n"
    +"Deuda personal: "+format(d["debt"],",.2f")+" MXN\n"
    +"Ingreso / gasto personal del mes: "+format(d["income"],",.2f")+" / "+format(d["expense"],",.2f")+" MXN\n"
    +"Efectivo de negocios (separado): "+format(d["business_cash"],",.2f")+" MXN\n\n"
    +"MIS PRIORIDADES\n- "+"\n- ".join(advice)
    +"\n\nLa distribución y proyección son estimaciones a partir de tus movimientos registrados. "
    +"No son instrucciones de inversión ni sustituyen revisar contratos y tasas. "
    +"Las transferencias propias no son ingresos; los retiros del negocio reducen su caja y aumentan el efectivo personal. "
    +"No ejecuto movimientos.")
    return {"answer":answer,"mode":"motor financiero basado en reglas; falta configurar OPENAI_API_KEY para IA generativa","ai_enabled":False}

@app.get("/api/travis/status")
def travis_status(user=Depends(auth)):
    return {"ai_enabled":bool(os.getenv("GROQ_API_KEY")),"provider":"Groq" if os.getenv("GROQ_API_KEY") else None,"model":os.getenv("GROQ_MODEL","openai/gpt-oss-120b") if os.getenv("GROQ_API_KEY") else None}

@app.get("/api/export")
def export(user=Depends(auth)): return get_data(user)
