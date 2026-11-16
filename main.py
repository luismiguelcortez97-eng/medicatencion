import os, hashlib, secrets, hmac
from datetime import datetime, timedelta, date
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET = os.getenv("APP_SECRET")
if not DATABASE_URL:
    raise RuntimeError("Falta configurar DATABASE_URL de Neon PostgreSQL")
if not SECRET:
    raise RuntimeError("APP_SECRET no configurado")

app = FastAPI(title="Control Financiero Personal", version="2.2.0")
app.mount("/static", StaticFiles(directory="static"), name="static")

@contextmanager
def con():
    with psycopg.connect(DATABASE_URL, sslmode="require", row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            yield cur

def init_db():
    statements = [
        """CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL, hash TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS businesses (
            id BIGSERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS accounts (
            id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
            scope TEXT NOT NULL, business_id BIGINT, balance DOUBLE PRECISION NOT NULL DEFAULT 0)""",
        """CREATE TABLE IF NOT EXISTS movements (
            id BIGSERIAL PRIMARY KEY, kind TEXT NOT NULL, scope TEXT NOT NULL,
            concept TEXT NOT NULL, amount DOUBLE PRECISION NOT NULL, day TEXT NOT NULL,
            account_id BIGINT, dest_id BIGINT, business_id BIGINT, category TEXT)""",
        """CREATE TABLE IF NOT EXISTS debts (
            id BIGSERIAL PRIMARY KEY, creditor TEXT NOT NULL, scope TEXT NOT NULL,
            business_id BIGINT, balance DOUBLE PRECISION NOT NULL DEFAULT 0,
            rate DOUBLE PRECISION DEFAULT 0, min_payment DOUBLE PRECISION DEFAULT 0,
            due_day INTEGER)""",
        """CREATE TABLE IF NOT EXISTS obligations (
            id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, scope TEXT NOT NULL,
            amount DOUBLE PRECISION NOT NULL, due_date TEXT NOT NULL,
            paid INTEGER NOT NULL DEFAULT 0)""",
        """CREATE TABLE IF NOT EXISTS budgets (
            id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, scope TEXT NOT NULL,
            category TEXT NOT NULL, monthly_limit DOUBLE PRECISION NOT NULL)"""
    ]
    with con() as c:
        for sql in statements:
            c.execute(sql)

init_db()

def auth(authorization: str | None = Header(default=None)):
    try:
        if not authorization or not authorization.startswith("Bearer "):
            raise ValueError()
        u, e, s = authorization[7:].split(".")
        payload = u + ":" + e
        expected = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if int(e) < int(datetime.utcnow().timestamp()) or not hmac.compare_digest(s, expected):
            raise ValueError()
        with con() as c:
            c.execute("SELECT id FROM users WHERE username=%s", (u,))
            if not c.fetchone():
                raise ValueError()
        return u
    except Exception:
        raise HTTPException(401, "Sesión inválida")

def make_token(u):
    exp = str(int((datetime.utcnow() + timedelta(hours=12)).timestamp()))
    payload = u + ":" + exp
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + "." + sig

class Cred(BaseModel):
    username: str = Field(min_length=3, max_length=60)
    password: str = Field(min_length=12, max_length=200)

class Data(BaseModel):
    data: dict

@app.get("/")
def home():
    return FileResponse("static/index.html")

@app.get("/health")
def health():
    with con() as c:
        c.execute("SELECT 1")
        c.fetchone()
    return {"ok": True, "database": "Neon PostgreSQL"}

@app.post("/api/register")
def register(x: Cred):
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", x.password.encode(), bytes.fromhex(salt), 310000).hex()
    try:
        with con() as c:
            c.execute("SELECT 1 FROM users LIMIT 1")
            if c.fetchone():
                raise HTTPException(403, "El registro inicial ya fue realizado")
            c.execute("INSERT INTO users(username,salt,hash) VALUES(%s,%s,%s)",
                      (x.username, salt, hashed))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409, "Ese usuario ya existe")
    return {"ok": True}

@app.post("/api/login")
def login(x: Cred):
    with con() as c:
        c.execute("SELECT * FROM users WHERE username=%s", (x.username,))
        u = c.fetchone()
    if not u or not hmac.compare_digest(
        hashlib.pbkdf2_hmac("sha256", x.password.encode(), bytes.fromhex(u["salt"]), 310000).hex(),
        u["hash"]
    ):
        raise HTTPException(401, "Credenciales incorrectas")
    return {"token": make_token(x.username)}

@app.get("/api/data")
def data(user=Depends(auth)):
    tables = ("businesses", "accounts", "movements", "debts", "obligations", "budgets")
    with con() as c:
        result = {}
        for table in tables:
            c.execute("SELECT * FROM " + table + " ORDER BY id")
            result[table] = c.fetchall()
        return result

@app.post("/api/{table}")
def add(table: str, x: Data, user=Depends(auth)):
    fields = {
        "businesses": ["name"],
        "accounts": ["name", "kind", "scope", "business_id", "balance"],
        "movements": ["kind", "scope", "concept", "amount", "day", "account_id", "dest_id", "business_id", "category"],
        "debts": ["creditor", "scope", "business_id", "balance", "rate", "min_payment", "due_day"],
        "obligations": ["name", "scope", "amount", "due_date"],
        "budgets": ["name", "scope", "category", "monthly_limit"]
    }
    if table not in fields:
        raise HTTPException(404, "Sección inválida")
    d = x.data
    keys = fields[table]
    if any(k not in d for k in keys):
        raise HTTPException(422, "Faltan campos")
    values = [d[k] for k in keys]
    columns = ",".join(keys)
    placeholders = ",".join(["%s"] * len(keys))
    with con() as c:
        c.execute(f"INSERT INTO {table} ({columns}) VALUES ({placeholders}) RETURNING id", values)
        row = c.fetchone()
    return {"id": row["id"]}

@app.post("/api/obligations/{oid}/paid")
def paid(oid: int, user=Depends(auth)):
    with con() as c:
        c.execute("UPDATE obligations SET paid=1 WHERE id=%s RETURNING id", (oid,))
        if not c.fetchone():
            raise HTTPException(404, "No encontrada")
    return {"ok": True}

@app.get("/api/dashboard")
def dashboard(user=Depends(auth)):
    month = date.today().strftime("%Y-%m")
    with con() as c:
        def total(sql, args=()):
            c.execute(sql, args)
            return c.fetchone()["v"] or 0
        return {
            "cash": total("SELECT COALESCE(SUM(balance),0) AS v FROM accounts WHERE scope='personal'"),
            "debt": total("SELECT COALESCE(SUM(balance),0) AS v FROM debts WHERE scope='personal'"),
            "income": total("SELECT COALESCE(SUM(amount),0) AS v FROM movements WHERE kind='income' AND scope='personal' AND substring(day,1,7)=%s", (month,)),
            "expense": total("SELECT COALESCE(SUM(amount),0) AS v FROM movements WHERE kind='expense' AND scope='personal' AND substring(day,1,7)=%s", (month,)),
            "obligations": total("SELECT COUNT(*) AS v FROM obligations WHERE paid=0")
        }

@app.post("/api/travis")
def travis(x: Data, user=Depends(auth)):
    d = dashboard(user)
    question = str(x.data.get("question", ""))[:1000]
    answer = ("Soy Travis. Cuentas personales $ {0:,.2f}; deuda $ {1:,.2f}; ingresos del mes $ {2:,.2f}; "
              "gastos $ {3:,.2f}; obligaciones pendientes {4}. Protege vencimientos y pagos mínimos "
              "antes de acelerar deudas. No consideres libre dinero reservado ni ingresos empresariales "
              "como personales. Pregunta: {5}").format(
        d["cash"], d["debt"], d["income"], d["expense"], d["obligations"], question
    )
    return {"answer": answer}

@app.get("/api/export")
def export(user=Depends(auth)):
    return data(user)
