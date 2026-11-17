import os, hmac, hashlib, secrets, json, urllib.request, urllib.error
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
    """CREATE TABLE IF NOT EXISTS budgets(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL,scope TEXT NOT NULL,category TEXT NOT NULL,monthly_limit DOUBLE PRECISION NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS assets(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL,scope TEXT NOT NULL,business_id BIGINT REFERENCES businesses(id),category TEXT NOT NULL,current_value DOUBLE PRECISION NOT NULL CHECK(current_value>=0))""",
    """CREATE TABLE IF NOT EXISTS financial_settings(id INTEGER PRIMARY KEY CHECK(id=1),emergency_months INTEGER NOT NULL DEFAULT 3 CHECK(emergency_months BETWEEN 1 AND 12))""",
    """ALTER TABLE accounts ADD COLUMN IF NOT EXISTS is_reserve BOOLEAN NOT NULL DEFAULT FALSE"""
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
            day=str(d.get("day") or date.today().isoformat())
            try: datetime.strptime(day,"%Y-%m-%d")
            except: raise HTTPException(422,"Fecha inválida.")
            item={"kind":k,"scope":sc,"amount":n,"account_id":d.get("account_id"),"dest_id":d.get("dest_id"),"business_id":d.get("business_id")}
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
        c.execute("UPDATE obligations SET paid=1 WHERE id=%s RETURNING id",(oid,))
        if not c.fetchone(): raise HTTPException(404,"Obligación no encontrada.")
    return {"ok":True}

@app.get("/api/dashboard")
def dashboard(user=Depends(auth)):
    month=date.today().strftime("%Y-%m")
    with con() as c:
        def total(sql,args=()):
            c.execute(sql,args); return float(c.fetchone()["v"] or 0)
        c.execute("SELECT emergency_months FROM financial_settings WHERE id=1"); setting=c.fetchone()
        emergency_months=int(setting["emergency_months"]) if setting else 3
        reserve=total("SELECT COALESCE(SUM(balance),0) v FROM accounts WHERE scope='personal' AND is_reserve=TRUE")
        monthly_expense_avg=total("SELECT COALESCE(SUM(amount),0)/3.0 v FROM movements WHERE kind='expense' AND scope='personal' AND day >= %s",( (date.today()-timedelta(days=90)).isoformat(), ))
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
        "overdue":total("SELECT COUNT(*) v FROM obligations WHERE paid=0 AND due_date<%s",(date.today().isoformat(),))
        }

@app.get("/api/insights")
def insights(user=Depends(auth)):
    today=date.today()
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

@app.post("/api/travis")
def travis(x:Data,user=Depends(auth)):
    question=str(x.data.get("question") or "").strip()[:1200]
    page=str(x.data.get("context") or "general")[:80]
    d=dashboard(user)
    ins=insights(user)
    snapshot={
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
    key=os.getenv("OPENAI_API_KEY")
    if key:
        model=os.getenv("OPENAI_MODEL","gpt-4o-mini")
        system=("Eres Travis, asesor y tutor financiero integral, riguroso y práctico, dentro de la aplicación Finanzas. "
        "Tienes dos responsabilidades: enseñar a usar el programa paso a paso y analizar finanzas personales y empresariales. "
        "CONOCIMIENTO DEL PROGRAMA: los módulos son Inicio/Panel general, Cuentas y movimientos, Negocios, Deudas, Fondo de emergencia, Distribución, Presupuestos, Proyección, Reportes y Travis. "
        "Orden recomendado: primero registra cada negocio; segundo crea cuentas personales y empresariales con sus saldos actuales; tercero captura deudas con acreedor, saldo, tasa/CAT conocida, pago mínimo y día de vencimiento; cuarto obligaciones próximas; quinto presupuestos; sexto movimientos diarios con fecha, concepto, importe, tipo, cuenta y categoría; séptimo activos y fondo de emergencia; finalmente revisa distribución, proyección y reportes. "
        "Si pregunta qué llenar primero, indica un único siguiente paso, dónde entrar, qué botón o campo usar, qué dato introducir y por qué importa. Si falta un dato, dile cómo conseguirlo y permite dejarlo pendiente; nunca inventes. Explica cada módulo, campo, cálculo, limitación y flujo de trabajo. No afirmes que existe una función que no esté descrita. "
        "Para aprovechar el programa, recomienda capturar movimientos constantemente, conciliar saldos con bancos y efectivo, separar cajas, registrar fechas reales, completar tasas y mínimos de deuda, actualizar obligaciones y revisar semanalmente alertas y flujo; revisar mensualmente presupuestos, distribución, proyección y reportes. "
        "CONOCIMIENTO FINANCIERO: aplica flujo de efectivo, liquidez, capital de trabajo, presupuesto base cero, fondo de emergencia, costo efectivo de deuda/CAT, métodos avalancha y bola de nieve, amortización, riesgo, diversificación, inflación, interés compuesto, patrimonio neto, rentabilidad y escenarios. Distingue educación general de recomendación personalizada; explica ventajas, riesgos, supuestos y datos faltantes. No recomiendes inversiones específicas sin conocer horizonte, tolerancia al riesgo, liquidez y jurisdicción. "
        "Analiza exclusivamente los datos entregados; si faltan datos dilo y pregunta solo lo indispensable. Responde en español mexicano, con prioridades concretas, cantidades en MXN y pasos accionables. Separa siempre finanzas personales y empresariales. Transferencias entre cuentas propias no son ingresos. Un retiro del negocio es ingreso personal pero no ingreso nuevo del negocio: reduce caja empresarial y aumenta la personal. "
        "No ordenes ni afirmes ejecutar pagos, transferencias o movimientos. No inventes tasas, CAT, fechas ni saldos. Considera liquidez, obligaciones vencidas, pagos mínimos, fondo de emergencia y riesgo. Explica supuestos y advierte cuando la muestra de 90 días sea insuficiente. "
        "Estructura respuestas complejas así: diagnóstico; qué significa; prioridad inmediata; pasos exactos dentro de la aplicación; dato faltante; cuándo volver a revisar.")
        payload={"model":model,"messages":[{"role":"system","content":system},
        {"role":"user","content":"Pestaña actual: "+page+"\nPregunta: "+(question or "Analiza mi situación y dime las tres prioridades.")+
        "\nDatos registrados (JSON): "+json.dumps(snapshot,ensure_ascii=False,default=str)}],
        "temperature":0.25,"max_tokens":1300}
        try:
            req=urllib.request.Request("https://api.openai.com/v1/chat/completions",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Authorization":"Bearer "+key,"Content-Type":"application/json"},
                method="POST")
            with urllib.request.urlopen(req,timeout=28) as response:
                result=json.loads(response.read().decode("utf-8"))
            answer=result["choices"][0]["message"]["content"].strip()
            return {"answer":answer,"mode":"IA generativa conectada","ai_enabled":True}
        except Exception:
            pass
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
    return {"ai_enabled":bool(os.getenv("OPENAI_API_KEY")),"model":os.getenv("OPENAI_MODEL","gpt-4o-mini") if os.getenv("OPENAI_API_KEY") else None}

@app.get("/api/export")
def export(user=Depends(auth)): return get_data(user)
