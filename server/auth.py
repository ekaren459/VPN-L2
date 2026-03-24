import os
import jwt
import bcrypt
import psycopg2
import datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
SECRET_KEY = os.environ.get("JWT_SECRET", "mi_clave_secreta_super_segura_2024")

def get_db():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "database"),
        database=os.environ.get("DB_NAME", "vpnl2"),
        user=os.environ.get("DB_USER", "vpnuser"),
        password=os.environ.get("DB_PASS", "vpnpass")
    )

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

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>VPN L2 - Login</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: Arial, sans-serif; background: #1a1a2e;
               display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .card { background: #16213e; padding: 40px; border-radius: 12px;
                width: 360px; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }
        h2 { color: #e94560; margin-bottom: 8px; }
        p  { color: #aaa; font-size: 13px; margin-bottom: 24px; }
        label { color: #ccc; font-size: 13px; display: block; margin-bottom: 6px; }
        input { width: 100%; padding: 10px 14px; border-radius: 8px;
                border: 1px solid #0f3460; background: #0f3460;
                color: #fff; font-size: 14px; margin-bottom: 16px; }
        button { width: 100%; padding: 12px; background: #e94560;
                 color: white; border: none; border-radius: 8px;
                 font-size: 15px; cursor: pointer; }
        button:hover { background: #c73652; }
        #msg { margin-top: 16px; font-size: 13px; text-align: center; }
        .error { color: #e94560; }
        .ok    { color: #4ecca3; }
    </style>
</head>
<body>
<div class="card">
    <h2>🔒 VPN L2</h2>
    <p>Ingresa tus credenciales para conectarte</p>
    <label>Usuario</label>
    <input type="text" id="user" placeholder="nombre_usuario" value="admin">
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
        msg.textContent = '✅ Login exitoso...';
        localStorage.setItem('vpn_token', data.token);
        setTimeout(() => window.location.href = '/dashboard', 1000);
    } else {
        msg.className = 'error';
        msg.textContent = '❌ ' + data.error;
    }
}
document.addEventListener('keypress', e => { if (e.key === 'Enter') login(); });
</script>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>VPN L2 - Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: Arial, sans-serif; background: #1a1a2e; color: #eee; padding: 30px; }
        h1  { color: #4ecca3; margin-bottom: 6px; }
        .subtitle { color: #666; font-size: 12px; margin-bottom: 20px; }
        .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
        .metric { background: #16213e; border-radius: 10px; padding: 16px; text-align: center; }
        .metric-val { font-size: 28px; font-weight: bold; color: #4ecca3; }
        .metric-lbl { font-size: 12px; color: #888; margin-top: 4px; }
        .section { background: #16213e; border-radius: 10px; padding: 16px; margin-bottom: 16px; }
        h3 { color: #e94560; margin-bottom: 12px; font-size: 14px; }
        table { border-collapse: collapse; width: 100%; }
        th { background: #0f3460; color: #4ecca3; padding: 8px 10px; text-align: left; font-size: 12px; }
        td { padding: 7px 10px; border-bottom: 1px solid #0f3460; font-size: 12px; color: #ccc; }
        tr:last-child td { border-bottom: none; }
        .badge-ok  { background: #4ecca3; color: #1a1a2e; padding: 2px 8px; border-radius: 10px; font-size: 10px; }
        .badge-err { background: #e94560; color: #fff;    padding: 2px 8px; border-radius: 10px; font-size: 10px; }
        .mac  { font-family: monospace; color: #4ecca3; }
        .ip   { font-family: monospace; color: #aaa; }
        .refresh { float: right; font-size: 11px; color: #555; }
        .token-box { background: #0f3460; border-radius: 6px; padding: 8px 10px;
                     font-size: 10px; color: #4ecca3; word-break: break-all; margin-bottom: 16px; }
        .btn-logout { background: #e94560; color: white; border: none; border-radius: 6px;
                      padding: 6px 14px; cursor: pointer; font-size: 12px; float: right; }
    </style>
</head>
<body>
<h1>🌐 VPN L2 — Panel de Control <button class="btn-logout" onclick="logout()">Cerrar sesión</button></h1>
<p class="subtitle" id="refresh-info">Actualizando cada 5 segundos...</p>

<div class="token-box" id="token-box">Cargando token...</div>

<div class="metrics">
    <div class="metric"><div class="metric-val" id="m-macs">—</div><div class="metric-lbl">MACs aprendidas</div></div>
    <div class="metric"><div class="metric-val" id="m-sesiones">—</div><div class="metric-lbl">Sesiones registradas</div></div>
    <div class="metric"><div class="metric-val" id="m-activas">—</div><div class="metric-lbl">Sesiones activas</div></div>
    <div class="metric"><div class="metric-val" id="m-cerradas">—</div><div class="metric-lbl">Sesiones cerradas</div></div>
</div>

<div class="section">
    <h3>Tabla MAC Cache <span class="refresh" id="mac-ts"></span></h3>
    <table>
        <thead><tr><th>MAC Address</th><th>VPort (IP:Puerto)</th><th>Último visto</th></tr></thead>
        <tbody id="tbody-mac"><tr><td colspan="3" style="color:#555">Cargando...</td></tr></tbody>
    </table>
</div>

<div class="section">
    <h3>Sesiones VPN <span class="refresh" id="ses-ts"></span></h3>
    <table>
        <thead><tr><th>ID</th><th>IP Pública</th><th>Inicio</th><th>Fin</th><th>Estado</th></tr></thead>
        <tbody id="tbody-ses"><tr><td colspan="5" style="color:#555">Cargando...</td></tr></tbody>
    </table>
</div>

<script>
const token = localStorage.getItem('vpn_token');
if (!token) { window.location.href = '/'; }

document.getElementById('token-box').textContent = 'JWT: ' + token;

function logout() {
    localStorage.removeItem('vpn_token');
    window.location.href = '/';
}

async function cargar() {
    try {
        const headers = { 'Authorization': 'Bearer ' + token };

        // MACs
        const r1 = await fetch('/api/mac-cache', { headers });
        if (r1.status === 401) { logout(); return; }
        const macs = await r1.json();
        document.getElementById('m-macs').textContent = macs.length;
        document.getElementById('mac-ts').textContent = new Date().toLocaleTimeString();
        const tbMac = document.getElementById('tbody-mac');
        if (macs.length === 0) {
            tbMac.innerHTML = '<tr><td colspan="3" style="color:#555">Sin MACs aprendidas — conecta un VPort</td></tr>';
        } else {
            tbMac.innerHTML = macs.map(m => `
                <tr>
                    <td><span class="mac">${m.mac_address}</span></td>
                    <td><span class="ip">${m.vport_addr}</span></td>
                    <td>${new Date(m.timestamp_ultimo_visto).toLocaleString()}</td>
                </tr>`).join('');
        }

        // Sesiones
        const r2 = await fetch('/api/sesiones', { headers });
        const ses = await r2.json();
        document.getElementById('m-sesiones').textContent = ses.length;
        document.getElementById('m-activas').textContent  = ses.filter(s => !s.timestamp_fin).length;
        document.getElementById('m-cerradas').textContent = ses.filter(s =>  s.timestamp_fin).length;
        document.getElementById('ses-ts').textContent = new Date().toLocaleTimeString();
        const tbSes = document.getElementById('tbody-ses');
        if (ses.length === 0) {
            tbSes.innerHTML = '<tr><td colspan="5" style="color:#555">Sin sesiones registradas</td></tr>';
        } else {
            tbSes.innerHTML = ses.map(s => `
                <tr>
                    <td>${s.id_device}</td>
                    <td><span class="ip">${s.ip_publica_cliente}</span></td>
                    <td>${new Date(s.timestamp_inicio).toLocaleString()}</td>
                    <td>${s.timestamp_fin ? new Date(s.timestamp_fin).toLocaleString() : '—'}</td>
                    <td>${s.timestamp_fin
                        ? '<span class="badge-err">Cerrada</span>'
                        : '<span class="badge-ok">Activa</span>'}</td>
                </tr>`).join('');
        }

    } catch(e) {
        document.getElementById('refresh-info').textContent = 'Error de conexión: ' + e.message;
    }
}

cargar();
setInterval(cargar, 5000);
</script>
</body>
</html>
"""

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
        cur.execute(
            "SELECT id_user, password_hash, activo FROM T_Usuarios WHERE nombre_usuario = %s",
            (datos["nombre_usuario"],)
        )
        usuario = cur.fetchone()
        if not usuario or not bcrypt.checkpw(datos["password"].encode(), usuario[1].encode()):
            return jsonify({"error": "Credenciales incorrectas"}), 401
        if not usuario[2]:
            return jsonify({"error": "Cuenta desactivada"}), 403

        expiracion = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        token = jwt.encode({"id_user": usuario[0], "exp": expiracion}, SECRET_KEY, algorithm="HS256")

        cur.execute(
            "INSERT INTO T_Tokens (id_user, token_string, fecha_expiracion) VALUES (%s, %s, %s)",
            (usuario[0], token, expiracion)
        )
        db.commit()
        db.close()
        print(f"[LOGIN] Usuario {usuario[0]} autenticado, token emitido")
        return jsonify({"token": token, "expira": expiracion.isoformat()})
    except Exception as e:
        print(f"[LOGIN] Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/mac-cache")
@requiere_token
def mac_cache():
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT mac_address, vport_addr, timestamp_ultimo_visto FROM T_Mac_Cache ORDER BY timestamp_ultimo_visto DESC"
        )
        rows = cur.fetchall()
        db.close()
        return jsonify([{
            "mac_address": r[0].strip(),
            "vport_addr": r[1],
            "timestamp_ultimo_visto": r[2].isoformat()
        } for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/sesiones")
@requiere_token
def sesiones():
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT id_device, ip_publica_cliente::text, timestamp_inicio, timestamp_fin FROM T_Sesiones ORDER BY timestamp_inicio DESC LIMIT 20"
        )
        rows = cur.fetchall()
        db.close()
        return jsonify([{
            "id_device": r[0],
            "ip_publica_cliente": r[1],
            "timestamp_inicio": r[2].isoformat(),
            "timestamp_fin": r[3].isoformat() if r[3] else None
        } for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/status")
def status():
    return jsonify({"status": "ok", "vswitch_port": 8888})

from vswitch import iniciar_vswitch
iniciar_vswitch()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
