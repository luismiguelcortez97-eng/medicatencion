# Control Financiero Personal

Aplicación independiente para registrar cuentas, movimientos, negocios, deudas, obligaciones y presupuestos. Incluye asistente inicial Travis.

## Despliegue
Render puede desplegar desde este repositorio usando render.yaml. Configura APP_SECRET como secreto largo y privado. SQLite requiere disco persistente; para uso serio conviene migrar a PostgreSQL administrado.

## Inicio local
Python 3.11+, instala requirements.txt, define APP_SECRET y ejecuta uvicorn main:app --reload. Crea el primer usuario desde la pantalla inicial con una contraseña de al menos 12 caracteres.

## Principios
- Separar caja personal y caja de cada negocio.
- Cubrir obligaciones y pagos mínimos antes de abonos extraordinarios.
- No tratar dinero reservado como capital libre.
- Travis orienta; no ejecuta pagos ni transferencias.

## Estado
Versión inicial de reemplazo. No usar todavía como contabilidad oficial ni almacenar información financiera sensible: requiere revisión de seguridad, pruebas contables, controles de propiedad de datos, conciliación, backups y migración a PostgreSQL antes de producción.
