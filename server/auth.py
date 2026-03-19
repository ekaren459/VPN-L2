import os
import jwt
import bcrypt
import psycopg2
import datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
SECRET_KEY = os.environ.get("JWT_SECRET", "clave_secreta_cambiar_en_produccion")

# --- Conexión a la base de datos ---
def get_db():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "database"),
        database=os.environ.get("DB_NAME", "vpnl2"),
        user=os.environ.get("DB_USER", "vpnuser"),
        password=os.environ.get("DB_PASS", "vpnpass")
    )

# --- Decorador para proteger rutas ---
def requiere_token(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"error": "Token requerido"}), 401
        try:
            datos = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.usuario = datos
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido"}), 401
        return f(*args, **kwargs)
    return decorador

# --- Página de login (HTML) ---
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>VPN L2 - Login</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: Arial, sans-serif; background: #1a1a2e; display: flex;
               justify-content: center; align-items: center; min-height: 100vh; }
        .card { background: #16213e; padding: 40px; border-radius: 12px;
                width: 360px; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }
        h2 { color: #e94560; margin-bottom: 8px; }
        p { color: #aaa; font-size: 13px; margin-bottom: 24px; }
        label { color: #ccc; font-size: 13px; display: block; margin-bottom: 6px; }
        input { width: 100%; padding: 10px 14px; border-radius: 8px;
                border: 1px solid #0f3460; background: #0f3460;
                color: #fff; font-size: 14px; margin-bottom: 16px; }
        button { width: 100%; padding: 12px; background: #e94560;
                 color: white; border: none; border-radius: 8px;
                 font-size: 15px; cursor: pointer; }
        button:hover { background: #c73652; }
        #msg { margin-top: 16px; font-size: 13px; text-align: center; }
        .error { color: #e94560; } .ok { color: #4ecca3; }
    </style>
</head>
<body>
<div class="card">
    <h2>🔒 VPN L2</h2>
    <p>Ingresa tus credenciales para conectarte</p>
    <label>Usuario</label>
    <input type="text" id="user" placeholder="nombre_usuario">
    <label>Contraseña</label>
    <input type="password" id="pass" placeholder="••••••••">
    <button onclick="login()">Iniciar sesión</button>
    <div id="msg"></div>
</div>
<script>
async function login() {
    const res = await fetch('/api/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            nombre_usuario: document.getElementById('user').value,
            password: document.getElementById('pass').value
        })
    });
    const data = await res.json();
    const msg = document.getElementById('msg');
    if (res.ok) {
        msg.className = 'ok';
        msg.textContent = '✅ Login exitoso. Token: ' + data.token.substring(0,30) + '...';
        localStorage.setItem('vpn_token', data.token);
        setTimeout(() => window.location.href = '/dashboard', 1500);
    } else {
        msg.className = 'error';
        msg.textContent = '❌ ' + data.error;
    }
}
</script>
</body>
</html>
"""

# --- Dashboard (requiere login) ---
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>VPN L2 - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background: #1a1a2e; color: #eee;
               padding: 40px; }
        h1 { color: #4ecca3; } h3 { color: #e94560; margin: 24px 0 12px; }
        table { border-collapse: collapse; width: 100%; max-width: 800px; }
        th { background: #0f3460; color: #4ecca3; padding: 10px; text-align: left; }
        td { padding: 8px 10px; border-bottom: 1px solid #0f3460; font-size: 13px; }
        .badge { background: #4ecca3; color: #1a1a2e; padding: 2px 8px;
                 border-radius: 12px; font-size: 11px; }
    </style>
</head>
<body>
    <h1>🌐 VPN L2 - Panel de Control</h1>
    <p id="token_display" style="font-size:11px; color:#555; word-break:break-all; 
   background:#0f3460; padding:8px; border-radius:6px; margin:8px 0 20px">
   Cargando token...
</p>
    <p id="usuario" style="color:#aaa; margin: 8px 0 0"></p>
    <h3>Tabla MAC Cache</h3>
    <table id="tabla_mac">
        <tr><th>MAC Address</th><th>VPort (IP:Puerto)</th><th>Último visto</th></tr>
    </table>
    <h3>Sesiones Activas</h3>
    <table id="tabla_sesiones">
        <tr><th>Dispositivo</th><th>IP Pública</th><th>Inicio</th><th>Estado</th></tr>
    </table>
<script>
const token = localStorage.getItem('vpn_token');
if (!token) window.location.href = '/';

async function cargarDatos() {
    const r1 = await fetch('/api/mac-cache', {headers: {'Authorization': 'Bearer ' + token}});
    if (r1.status === 401) { window.location.href = '/'; return; }
    const macs = await r1.json();
    const tm = document.getElementById('tabla_mac');
    macs.forEach(m => {
        const tr = tm.insertRow();
        tr.insertCell().textContent = m.mac_address;
        tr.insertCell().textContent = m.vport_addr;
        tr.insertCell().textContent = new Date(m.timestamp_ultimo_visto).toLocaleString();
    });

    const r2 = await fetch('/api/sesiones', {headers: {'Authorization': 'Bearer ' + token}});
    const ses = await r2.json();
    const ts = document.getElementById('tabla_sesiones');
    ses.forEach(s => {
        const tr = ts.insertRow();
        tr.insertCell().textContent = s.id_device;
        tr.insertCell().textContent = s.ip_publica_cliente;
        tr.insertCell().textContent = new Date(s.timestamp_inicio).toLocaleString();
        const td = tr.insertCell();
        td.innerHTML = s.timestamp_fin ? 'Cerrada' : '<span class="badge">Activa</span>';
    });
}
cargarDatos();
</script>
</body>
</html>
"""

# --- Rutas ---
@app.route("/")
def index():
    return render_template_string(LOGIN_HTML)

@app.route("/dashboard")
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route("/api/login", methods=["POST"])
def login():
    datos = request.json
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id_user, password_hash, activo FROM T_Usuarios WHERE nombre_usuario = %s",
                    (datos["nombre_usuario"],))
        usuario = cur.fetchone()
        if not usuario or not bcrypt.checkpw(datos["password"].encode(), usuario[1].encode()):
            return jsonify({"error": "Credenciales incorrectas"}), 401
        if not usuario[2]:
            return jsonify({"error": "Cuenta desactivada"}), 403

        expiracion = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        token = jwt.encode({"id_user": usuario[0], "exp": expiracion}, SECRET_KEY, algorithm="HS256")

        cur.execute("""INSERT INTO T_Tokens (id_user, token_string, fecha_expiracion)
                       VALUES (%s, %s, %s)""", (usuario[0], token, expiracion))
        db.commit()
        return jsonify({"token": token, "expira": expiracion.isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/mac-cache")
@requiere_token
def mac_cache():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT mac_address, vport_addr, timestamp_ultimo_visto FROM T_Mac_Cache ORDER BY timestamp_ultimo_visto DESC")
    rows = cur.fetchall()
    return jsonify([{"mac_address": r[0], "vport_addr": r[1], "timestamp_ultimo_visto": r[2].isoformat()} for r in rows])

@app.route("/api/sesiones")
@requiere_token
def sesiones():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id_device, ip_publica_cliente::text, timestamp_inicio, timestamp_fin FROM T_Sesiones ORDER BY timestamp_inicio DESC LIMIT 20")
    rows = cur.fetchall()
    return jsonify([{"id_device": r[0], "ip_publica_cliente": r[1],
                     "timestamp_inicio": r[2].isoformat(),
                     "timestamp_fin": r[3].isoformat() if r[3] else None} for r in rows])

from vswitch import iniciar_vswitch
iniciar_vswitch()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)