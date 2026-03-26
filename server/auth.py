import os
import re
import jwt
import bcrypt
import psycopg2
import datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
SECRET_KEY = os.environ.get("JWT_SECRET", "clave_secreta_cambiar_en_produccion")

@app.after_request
def no_cache_headers(resp):
    # Evita que el navegador reutilice páginas autenticadas desde caché/historial.
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPN L2 - Login</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #f4f7fb;
            --card: #ffffff;
            --border: #e5e7eb;
            --txt-main: #111827;
            --txt-muted: #6b7280;
            --blue: #2563eb;
            --green: #16a34a;
            --danger: #dc2626;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
            color: var(--txt-main);
        }
        .wrap { width: 100%; max-width: 420px; }
        .title {
            text-align: center;
            margin-bottom: 14px;
        }
        .title h2 {
            font-size: 1.9rem;
            letter-spacing: -0.5px;
            margin-bottom: 4px;
        }
        .title p {
            color: var(--txt-muted);
            font-size: 0.92rem;
        }
        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
            padding: 24px;
        }
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            border-radius: 999px;
            padding: 6px 10px;
            border: 1px solid #dbeee1;
            color: #166534;
            font-size: 0.78rem;
            font-weight: 600;
            background: #f2fbf5;
            margin-bottom: 14px;
        }
        .dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--green);
        }
        label {
            color: var(--txt-main);
            font-size: 0.86rem;
            font-weight: 600;
            display: block;
            margin-bottom: 7px;
        }
        input {
            width: 100%;
            padding: 11px 13px;
            border-radius: 10px;
            border: 1px solid var(--border);
            background: #fff;
            color: var(--txt-main);
            font-size: 0.92rem;
            margin-bottom: 14px;
            outline: none;
        }
        input:focus {
            border-color: #bfdbfe;
            box-shadow: 0 0 0 3px #eff6ff;
        }
        button {
            width: 100%;
            padding: 11px;
            background: var(--blue);
            color: #fff;
            border: none;
            border-radius: 10px;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
        }
        button:hover { filter: brightness(0.95); }
        .btn-secondary {
            margin-top: 10px;
            background: #eef2ff;
            color: #1e3a8a;
            border: 1px solid #c7d2fe;
        }
        .text-link {
            margin-top: 10px;
            display: block;
            text-align: center;
            color: #1d4ed8;
            font-size: 0.84rem;
            text-decoration: none;
            font-weight: 600;
            cursor: pointer;
        }
        .text-link:hover { text-decoration: underline; }
        #msg {
            margin-top: 12px;
            font-size: 0.84rem;
            text-align: center;
            min-height: 1.2em;
        }
        .error { color: var(--danger); }
        .ok { color: var(--green); }
    </style>
</head>
<body>
<div class="wrap">
  <div class="title">
    <img src="{{ url_for('static', filename='./img/logo.jpeg') }}" alt="Encava VPN" style="width: 120px; margin-bottom: 10px;">
    <p>Acceso al panel de administración</p>
</div>
    <div class="card">
        <div class="badge"><span class="dot"></span><span>Servicio en vivo</span></div>
        <label>Usuario</label>
        <input type="text" id="user" placeholder="nombre_usuario" autocomplete="username">
        <label>Contraseña</label>
        <input type="password" id="pass" placeholder="••••••••" autocomplete="current-password">
        <button onclick="login()">Iniciar sesión</button>
        <button class="btn-secondary" onclick="irARegistro()">Crear nuevo usuario</button>
        <a class="text-link" onclick="irARecuperar()">¿Olvidaste tu contraseña?</a>
        <div id="msg"></div>
    </div>
</div>
<script>
function irARegistro() {
    window.location.href = '/registro';
}

function irARecuperar() {
    window.location.href = '/recuperar-password';
}

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
        msg.textContent = 'Login exitoso. Redirigiendo al dashboard...';
        sessionStorage.setItem('vpn_token', data.token);
        sessionStorage.setItem('vpn_user', data.nombre_usuario || document.getElementById('user').value);
        setTimeout(() => window.location.href = '/dashboard', 900);
    } else {
        msg.className = 'error';
        msg.textContent = data.error || 'No se pudo iniciar sesión';
    }
}
</script>
</body>
</html>
"""

RECUPERAR_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPN L2 - Recuperar contraseña</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #f4f7fb;
            --card: #ffffff;
            --border: #e5e7eb;
            --txt-main: #111827;
            --txt-muted: #6b7280;
            --blue: #2563eb;
            --green: #16a34a;
            --danger: #dc2626;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
            color: var(--txt-main);
        }
        .wrap { width: 100%; max-width: 460px; }
        .title { text-align: center; margin-bottom: 14px; }
        .title h2 { font-size: 1.8rem; letter-spacing: -0.5px; margin-bottom: 4px; }
        .title p { color: var(--txt-muted); font-size: 0.92rem; }
        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
            padding: 24px;
        }
        label { color: var(--txt-main); font-size: 0.86rem; font-weight: 600; display: block; margin-bottom: 7px; }
        input {
            width: 100%;
            padding: 11px 13px;
            border-radius: 10px;
            border: 1px solid var(--border);
            background: #fff;
            color: var(--txt-main);
            font-size: 0.92rem;
            margin-bottom: 14px;
            outline: none;
        }
        input:focus { border-color: #bfdbfe; box-shadow: 0 0 0 3px #eff6ff; }
        button {
            width: 100%;
            padding: 11px;
            background: var(--blue);
            color: #fff;
            border: none;
            border-radius: 10px;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            margin-bottom: 10px;
        }
        .btn-secondary { background: #eef2ff; color: #1e3a8a; border: 1px solid #c7d2fe; }
        .strength {
            margin: -6px 0 12px 0;
        }
        .strength-bar {
            width: 100%;
            height: 8px;
            border-radius: 999px;
            background: #e5e7eb;
            overflow: hidden;
            border: 1px solid #e5e7eb;
        }
        .strength-fill {
            height: 100%;
            width: 0%;
            background: #ef4444;
            transition: width 0.2s ease, background 0.2s ease;
        }
        .strength-text {
            margin-top: 6px;
            font-size: 0.78rem;
            color: var(--txt-muted);
        }
        #msg { margin-top: 8px; font-size: 0.84rem; text-align: center; min-height: 1.2em; }
        .error { color: var(--danger); } .ok { color: var(--green); }
        .step-hidden { display: none; }
        .input-wrapper { position: relative; margin-bottom: 14px; }
        .input-wrapper input { margin-bottom: 0; padding-right: 40px; }
        .btn-eye {
            position: absolute; right: 12px; top: 12px;
            background: transparent; border: none; color: #6b7280;
            cursor: pointer; width: auto; margin: 0; padding: 0;
        }
        .btn-eye:hover { color: #374151; }
    </style>
</head>
<body>
<div class="wrap">
    <div class="title">
        <h2>Recuperar contraseña</h2>
        <p id="subtitle">Paso 1: Validar identidad</p>
    </div>
    <div class="card">
        <div id="step1">
            <label>Nombre de usuario</label>
            <input type="text" id="user" placeholder="nombre_usuario" autocomplete="username">
            <label>Correo electrónico</label>
            <input type="email" id="email" placeholder="usuario@dominio.com" autocomplete="email">
            <button onclick="verificar()">Verificar usuario</button>
        </div>

        <div id="step2" class="step-hidden">
            <label>Nueva contraseña</label>
            <div class="input-wrapper">
                <input type="password" id="new_pass" placeholder="••••••••" autocomplete="new-password" oninput="actualizarFuerza()">
                <button type="button" class="btn-eye" onclick="togglePass('new_pass')" tabindex="-1">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                </button>
            </div>
            <div class="strength">
                <div class="strength-bar"><div id="strength_fill" class="strength-fill"></div></div>
                <div id="strength_text" class="strength-text">Seguridad: muy baja</div>
            </div>
            <label>Confirmar contraseña</label>
            <div class="input-wrapper">
                <input type="password" id="confirm_pass" placeholder="••••••••" autocomplete="new-password">
                <button type="button" class="btn-eye" onclick="togglePass('confirm_pass')" tabindex="-1">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                </button>
            </div>
            <button onclick="recuperar()">Actualizar contraseña</button>
        </div>

        <button class="btn-secondary" onclick="volverLogin()">Volver al login</button>
        <div id="msg"></div>
    </div>
</div>
<script>
function volverLogin() { window.location.href = '/'; }

function togglePass(id) {
    const input = document.getElementById(id);
    input.type = input.type === 'password' ? 'text' : 'password';
}

async function verificar() {
    const msg = document.getElementById('msg');
    const user = document.getElementById('user').value.trim();
    const email = document.getElementById('email').value.trim();
    
    msg.textContent = '';
    msg.className = '';

    if (!user || !email) {
        msg.className = 'error';
        msg.textContent = 'Ingrese usuario y correo';
        return;
    }

    try {
        const res = await fetch('/api/validar-usuario', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({nombre_usuario: user, email: email})
        });
        const data = await res.json();

        if (res.ok) {
            document.getElementById('step1').classList.add('step-hidden');
            document.getElementById('step2').classList.remove('step-hidden');
            document.getElementById('subtitle').textContent = 'Paso 2: Nueva contraseña';
            msg.textContent = '';
        } else {
            msg.className = 'error';
            msg.textContent = data.error || 'Usuario no encontrado';
        }
    } catch (e) {
        msg.className = 'error';
        msg.textContent = 'Error de conexión';
    }
}

function evaluarPassword(pwd) {
    let score = 0;
    if (pwd.length >= 8) score += 1;
    if (/[A-Z]/.test(pwd)) score += 1;
    if (/[0-9]/.test(pwd)) score += 1;
    if (/[^A-Za-z0-9]/.test(pwd)) score += 1;
    return score;
}

function actualizarFuerza() {
    const pwd = document.getElementById('new_pass').value;
    const score = evaluarPassword(pwd);
    const fill = document.getElementById('strength_fill');
    const txt = document.getElementById('strength_text');

    const widths = ['10%', '30%', '55%', '78%', '100%'];
    const colors = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#16a34a'];
    const labels = ['muy baja', 'baja', 'media', 'alta', 'muy alta'];
    fill.style.width = widths[score];
    fill.style.background = colors[score];
    txt.textContent = 'Seguridad: ' + labels[score];
}

async function recuperar() {
    const msg = document.getElementById('msg');
    const nombre_usuario = document.getElementById('user').value.trim();
    const email = document.getElementById('email').value.trim();
    const nueva_password = document.getElementById('new_pass').value;
    const confirmar_password = document.getElementById('confirm_pass').value;

    if (!nueva_password || !confirmar_password) {
        msg.className = 'error';
        msg.textContent = 'Ingrese la nueva contraseña';
        return;
    }
    if (nueva_password !== confirmar_password) {
        msg.className = 'error';
        msg.textContent = 'Las contraseñas no coinciden';
        return;
    }
    if (
        nueva_password.length < 8 ||
        !/[A-Z]/.test(nueva_password) ||
        !/[0-9]/.test(nueva_password) ||
        !/[^A-Za-z0-9]/.test(nueva_password)
    ) {
        msg.className = 'error';
        msg.textContent = 'La contraseña debe tener minimo 8 caracteres, 1 mayuscula, 1 numero y 1 caracter especial';
        return;
    }

    const res = await fetch('/api/recuperar-password', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({nombre_usuario, email, nueva_password})
    });
    const data = await res.json();
    if (res.ok) {
        msg.className = 'ok';
        msg.textContent = 'Contraseña actualizada. Redirigiendo al login...';
        setTimeout(() => window.location.href = '/', 1200);
    } else {
        msg.className = 'error';
        msg.textContent = data.error || 'No se pudo actualizar la contraseña';
    }
}
</script>
</body>
</html>
"""

REGISTRO_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPN L2 - Registro</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #f4f7fb;
            --card: #ffffff;
            --border: #e5e7eb;
            --txt-main: #111827;
            --txt-muted: #6b7280;
            --blue: #2563eb;
            --green: #16a34a;
            --danger: #dc2626;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
            color: var(--txt-main);
        }
        .wrap { width: 100%; max-width: 460px; }
        .title { text-align: center; margin-bottom: 14px; }
        .title h2 { font-size: 1.9rem; letter-spacing: -0.5px; margin-bottom: 4px; }
        .title p { color: var(--txt-muted); font-size: 0.92rem; }
        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
            padding: 24px;
        }
        label {
            color: var(--txt-main);
            font-size: 0.86rem;
            font-weight: 600;
            display: block;
            margin-bottom: 7px;
        }
        input {
            width: 100%;
            padding: 11px 13px;
            border-radius: 10px;
            border: 1px solid var(--border);
            background: #fff;
            color: var(--txt-main);
            font-size: 0.92rem;
            margin-bottom: 14px;
            outline: none;
        }
        input:focus {
            border-color: #bfdbfe;
            box-shadow: 0 0 0 3px #eff6ff;
        }
        button {
            width: 100%;
            padding: 11px;
            background: var(--blue);
            color: #fff;
            border: none;
            border-radius: 10px;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            margin-bottom: 10px;
        }
        button:hover { filter: brightness(0.95); }
        .btn-secondary {
            background: #eef2ff;
            color: #1e3a8a;
            border: 1px solid #c7d2fe;
        }
        .strength { margin: -6px 0 12px 0; }
        .strength-bar { width: 100%; height: 8px; border-radius: 999px; background: #e5e7eb; overflow: hidden; border: 1px solid #e5e7eb; }
        .strength-fill { height: 100%; width: 0%; background: #ef4444; transition: width 0.2s ease, background 0.2s ease; }
        .strength-text { margin-top: 6px; font-size: 0.78rem; color: var(--txt-muted); }
        #msg {
            margin-top: 8px;
            font-size: 0.84rem;
            text-align: center;
            min-height: 1.2em;
        }
        .error { color: var(--danger); }
        .ok { color: var(--green); }
        .input-wrapper { position: relative; margin-bottom: 14px; }
        .input-wrapper input { margin-bottom: 0; padding-right: 40px; }
        .btn-eye {
            position: absolute; right: 12px; top: 12px;
            background: transparent; border: none; color: #6b7280;
            cursor: pointer; width: auto; margin: 0; padding: 0;
        }
        .btn-eye:hover { color: #374151; }
    </style>
</head>
<body>
<div class="wrap">
   <div class="title">
    <img src="{{ url_for('static', filename='./img/logo.jpeg') }}" alt="Encava VPN" style="width: 120px; margin-bottom: 10px;">
    <p>Completa los datos para registrar tu cuenta</p>
</div>
    <div class="card">
        <label>Nombre de usuario</label>
        <input type="text" id="user" placeholder="usuario" autocomplete="username">
        <label>Correo electrónico</label>
        <input type="email" id="email" placeholder="usuario@dominio.com" autocomplete="email">
        <label>Contraseña</label>
        <div class="input-wrapper">
            <input type="password" id="pass" placeholder="••••••••" autocomplete="new-password" oninput="actualizarFuerza()">
            <button type="button" class="btn-eye" onclick="togglePass('pass')" tabindex="-1">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
            </button>
        </div>
        <div class="strength">
            <div class="strength-bar"><div id="strength_fill" class="strength-fill"></div></div>
            <div id="strength_text" class="strength-text">Seguridad: muy baja</div>
        </div>
        <label>Confirmar contraseña</label>
        <div class="input-wrapper">
            <input type="password" id="confirm_pass" placeholder="••••••••" autocomplete="new-password">
            <button type="button" class="btn-eye" onclick="togglePass('confirm_pass')" tabindex="-1">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
            </button>
        </div>
        <button onclick="registrar()">Registrarme</button>
        <button class="btn-secondary" onclick="volverLogin()">Volver al login</button>
        <div id="msg"></div>
    </div>
</div>
<script>
function volverLogin() {
    window.location.href = '/';
}

function togglePass(id) {
    const input = document.getElementById(id);
    input.type = input.type === 'password' ? 'text' : 'password';
}

function evaluarPassword(pwd) {
    let score = 0;
    if (pwd.length >= 8) score += 1;
    if (/[A-Z]/.test(pwd)) score += 1;
    if (/[0-9]/.test(pwd)) score += 1;
    if (/[^A-Za-z0-9]/.test(pwd)) score += 1;
    return score;
}

function actualizarFuerza() {
    const pwd = document.getElementById('pass').value;
    const score = evaluarPassword(pwd);
    const fill = document.getElementById('strength_fill');
    const txt = document.getElementById('strength_text');

    const widths = ['10%', '30%', '55%', '78%', '100%'];
    const colors = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#16a34a'];
    const labels = ['muy baja', 'baja', 'media', 'alta', 'muy alta'];
    fill.style.width = widths[score];
    fill.style.background = colors[score];
    txt.textContent = 'Seguridad: ' + labels[score];
}

async function registrar() {
    const msg = document.getElementById('msg');
    msg.className = '';
    msg.textContent = '';

    const nombre_usuario = document.getElementById('user').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('pass').value;
    const confirm = document.getElementById('confirm_pass').value;

    if (!nombre_usuario || !email || !password || !confirm) {
        msg.className = 'error';
        msg.textContent = 'Todos los campos son obligatorios';
        return;
    }
    if (password !== confirm) {
        msg.className = 'error';
        msg.textContent = 'Las contraseñas no coinciden';
        return;
    }
    if (password.length < 6) {
        msg.className = 'error';
        msg.textContent = 'La contraseña debe tener al menos 6 caracteres';
        return;
    }

    const res = await fetch('/api/registro', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({nombre_usuario, email, password})
    });
    const data = await res.json();

    if (res.ok) {
        msg.className = 'ok';
        msg.textContent = 'Usuario creado correctamente. Redirigiendo al login...';
        setTimeout(() => window.location.href = '/', 1200);
    } else {
        msg.className = 'error';
        msg.textContent = data.error || 'No se pudo registrar el usuario';
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPN Capa 2 - Docker</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg: #f4f7fb;
            --card: #ffffff;
            --border: #e5e7eb;
            --txt-main: #111827;
            --txt-muted: #6b7280;
            --blue: #2563eb;
            --green: #16a34a;
            --orange: #ea580c;
            --soft-green: #eefbf2;
            --soft-orange: #fff7ed;
            --note: #eff6ff;
            --danger: #dc2626;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg);
            color: var(--txt-main);
            min-height: 100vh;
            padding: 24px;
        }
        .container { max-width: 1120px; margin: 0 auto; display: grid; gap: 18px; }
        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
        }
        .header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; padding: 4px 2px; }
        .title h1 { font-size: 2.45rem; font-weight: 700; letter-spacing: -0.6px; }
        .title p { margin-top: 6px; color: var(--txt-muted); font-size: 0.92rem; }
        .header-actions { display: flex; align-items: center; gap: 10px; }
        .live {
            display: inline-flex; align-items: center; gap: 8px;
            border-radius: 999px; padding: 8px 12px;
            border: 1px solid #dbeee1; color: #166534;
            font-size: 0.82rem; font-weight: 600; background: #f2fbf5;
        }
        .btn-logout {
            border: 1px solid #fecaca;
            color: #b91c1c;
            background: #fff1f2;
            border-radius: 10px;
            padding: 8px 12px;
            font-weight: 600;
            font-size: 0.82rem;
            cursor: pointer;
        }
        .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); }
        .panel { padding: 22px; }
        .panel h3 { font-size: 1rem; margin-bottom: 4px; }
        .panel p { color: var(--txt-muted); font-size: 0.84rem; margin-bottom: 14px; }
        .total-card .k { color: #111827; font-weight: 600; font-size: 1.55rem; margin-bottom: 20px; }
        .total-card .v { color: var(--blue); font-size: 3rem; font-weight: 700; letter-spacing: -1px; }
        .total-card .s { margin-top: 8px; color: var(--txt-muted); font-size: 0.86rem; }
        .chart-card canvas { width: 100% !important; height: 290px !important; }
        .device-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
        .dev-card { padding: 18px; }
        .dev-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .dev-id { display: flex; gap: 10px; align-items: center; }
        .avatar { width: 38px; height: 38px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; color: #fff; font-weight: 700; font-size: 0.8rem; }
        .avatar.p1 { background: #3b82f6; }
        .avatar.p2 { background: #f97316; }
        .dev-name { font-weight: 700; }
        .dev-ip { font-size: 0.82rem; color: var(--txt-muted); }
        .status { background: #22c55e; color: white; border-radius: 999px; font-size: 0.75rem; padding: 4px 10px; font-weight: 600; }
        .row { display: flex; justify-content: space-between; align-items: center; border-radius: 10px; padding: 10px 12px; margin-bottom: 8px; }
        .row.r { background: var(--soft-green); color: var(--green); }
        .row.e { background: var(--soft-orange); color: var(--orange); }
        .row .lbl { color: #111827; font-weight: 600; font-size: 0.9rem; }
        .row .val { font-weight: 700; font-size: 1.05rem; }
        .tot { border-top: 1px solid var(--border); margin-top: 10px; padding-top: 8px; display: flex; justify-content: space-between; color: #111827; font-weight: 700; }
        .note { background: var(--note); border: 1px solid #dbeafe; border-radius: 12px; padding: 14px 16px; color: #1e3a8a; font-size: 0.86rem; }
        .note strong { color: #1d4ed8; }
        .token-strip {
            background: #eff6ff;
            border: 1px solid #dbeafe;
            border-radius: 10px;
            padding: 10px 12px;
            color: #1d4ed8;
            font-size: 0.78rem;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
        .kpi { background: #f8fafc; border: 1px solid var(--border); border-radius: 10px; padding: 12px; }
        .kpi .n { font-size: 1.6rem; font-weight: 700; color: var(--blue); line-height: 1; }
        .kpi .l { margin-top: 6px; color: var(--txt-muted); font-size: 0.82rem; font-weight: 600; }
        .data-table { width: 100%; border-collapse: collapse; border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
        .data-table th, .data-table td { text-align: left; padding: 9px 10px; font-size: 0.84rem; border-bottom: 1px solid var(--border); }
        .data-table th { background: #f1f5f9; color: #334155; font-weight: 700; }
        .status-chip {
            display: inline-block;
            border-radius: 999px;
            padding: 2px 8px;
            font-size: 0.74rem;
            font-weight: 700;
        }
        .status-open { background: #dcfce7; color: #166534; }
        .status-closed { background: #fee2e2; color: #991b1b; }
        .err { color: var(--danger); font-size: 0.82rem; margin-top: 10px; min-height: 1em; }
        @media (max-width: 768px) {
            .title h1 { font-size: 1.8rem; }
            .device-grid { grid-template-columns: 1fr; }
            .kpi-grid { grid-template-columns: 1fr 1fr; }
            .header { flex-direction: column; align-items: flex-start; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">
                <img src="{{ url_for('static', filename='./img/logo.jpeg') }}" alt="Encava VPN" style="width: 180px; height: auto; display: block;">
                <p><strong>Usuario:</strong> <span id="logged_user">--</span></p>
                <p id="last_update">Actualizado: --:--:-- (cada 5s)</p>
            </div>
            <div class="header-actions">
                <div class="live"><span class="dot"></span><span>En vivo</span></div>
                <button class="btn-logout" onclick="cerrarSesion()">Cerrar sesión</button>
            </div>  
        </div>
        <div class="token-strip" id="token_preview">JWT: --</div>
        <div class="kpi-grid">
            <div class="kpi"><div class="n" id="kpi_mac">0</div><div class="l">MACs aprendidas</div></div>
            <div class="kpi"><div class="n" id="kpi_ses_total">0</div><div class="l">Sesiones registradas</div></div>
            <div class="kpi"><div class="n" id="kpi_ses_act">0</div><div class="l">Sesiones activas</div></div>
            <div class="kpi"><div class="n" id="kpi_ses_cer">0</div><div class="l">Sesiones cerradas</div></div>
        </div>
        <div class="card panel total-card">
            <div class="k">Total Transferido</div>
            <div class="v" id="total_transfer">0.00 MB</div>
            <div class="s">Throughput estimado: <span id="rate">0.00 Mbps</span></div>
        </div>
        <div class="card panel chart-card">
            <h3>Tráfico de Red en Tiempo Real</h3>
            <p>Transferencia de datos entre contenedores (últimos 100 segundos)</p>
            <canvas id="trafficChart"></canvas>
            <div id="errorBox" class="err"></div>
        </div>
        <div class="device-grid">
            <div class="card dev-card" id="pc1_card">
                <div class="dev-head">
                    <div class="dev-id">
                        <div class="avatar p1">PC</div>
                        <div><div class="dev-name" id="pc1_name">PC-1</div><div class="dev-ip" id="pc1_ip">-</div></div>
                    </div>
                    <div class="status" id="pc1_status">connected</div>
                </div>
                <div class="row r"><div class="lbl">Recibidos</div><div class="val" id="pc1_rx">0.00 MB</div></div>
                <div class="row e"><div class="lbl">Enviados</div><div class="val" id="pc1_tx">0.00 MB</div></div>
                <div class="tot"><span>Total:</span><span id="pc1_total">0.00 MB</span></div>
            </div>
            <div class="card dev-card" id="pc2_card">
                <div class="dev-head">
                    <div class="dev-id">
                        <div class="avatar p2">PC</div>
                        <div><div class="dev-name" id="pc2_name">PC-2</div><div class="dev-ip" id="pc2_ip">-</div></div>
                    </div>
                    <div class="status" id="pc2_status">connected</div>
                </div>
                <div class="row r"><div class="lbl">Recibidos</div><div class="val" id="pc2_rx">0.00 MB</div></div>
                <div class="row e"><div class="lbl">Enviados</div><div class="val" id="pc2_tx">0.00 MB</div></div>
                <div class="tot"><span>Total:</span><span id="pc2_total">0.00 MB</span></div>
            </div>
        </div>
        <div class="note">
            <strong>Conexión con Flask:</strong> esta vista usa `/api/sesiones` y `/api/mac-cache` para actualizar métricas y tarjetas en tiempo real.
            Sesiones activas: <span id="active_sessions">0</span> · Entradas MAC: <span id="mac_count">0</span>
        </div>
        <div class="card panel">
            <h3>Tabla MAC Cache</h3>
            <table class="data-table">
                <thead>
                    <tr><th>MAC Address</th><th>VPort (IP:Puerto)</th><th>Último visto</th></tr>
                </thead>
                <tbody id="mac_table_body">
                    <tr><td colspan="3">Sin datos</td></tr>
                </tbody>
            </table>
        </div>
        <div class="card panel">
            <h3>Sesiones VPN</h3>
            <table class="data-table">
                <thead>
                    <tr><th>ID</th><th>IP pública</th><th>Inicio</th><th>Fin</th><th>Estado</th></tr>
                </thead>
                <tbody id="ses_table_body">
                    <tr><td colspan="5">Sin datos</td></tr>
                </tbody>
            </table>
        </div>
    </div>
<script>
    const token = sessionStorage.getItem('vpn_token');
    if (!token) window.location.href = '/';
    const loggedUser = sessionStorage.getItem('vpn_user');
    document.getElementById('logged_user').textContent = loggedUser || 'Desconocido';
    document.getElementById('token_preview').textContent = 'JWT: ' + token;
    history.pushState({auth: true}, '', window.location.href);

    window.addEventListener('popstate', () => {
        sessionStorage.removeItem('vpn_token');
        sessionStorage.removeItem('vpn_user');
        window.location.href = '/';
    });

    window.addEventListener('pagehide', () => {
        sessionStorage.removeItem('vpn_token');
        sessionStorage.removeItem('vpn_user');
    });

    function cerrarSesion() {
        sessionStorage.removeItem('vpn_token');
        sessionStorage.removeItem('vpn_user');
        window.location.href = '/';
    }
    let prevTotalBytes = 0;
    let prevTs = null;

    const ctx = document.getElementById('trafficChart').getContext('2d');
    const trafficChart = new Chart(ctx, {
        type: 'line',
        data: { labels: [], datasets: [{ label: 'Transferencia', borderColor: '#c97d3a', backgroundColor: 'rgba(201, 125, 58, 0.08)', data: [], borderWidth: 2.4, tension: 0.35, fill: false, pointRadius: 0 }] },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom', labels: { usePointStyle: true, boxWidth: 8, color: '#64748b' } } },
            scales: {
                x: { grid: { color: '#f1f5f9' }, ticks: { color: '#9ca3af' } },
                y: { beginAtZero: true, grid: { color: '#f1f5f9' }, ticks: { color: '#9ca3af', callback: (v) => v.toFixed ? v.toFixed(2) + ' MB' : v + ' MB' } }
            }
        }
    });

    function fmtDate(iso) { return iso ? new Date(iso).toLocaleString() : '-'; }
    function fmtMB(bytes) { return (bytes / (1024 * 1024)).toFixed(2) + ' MB'; }

    async function cargarDatos() {
        const errorBox = document.getElementById('errorBox');
        errorBox.textContent = '';
        try {
            const [resSes, resMac] = await Promise.all([
                fetch('/api/sesiones', { headers: {'Authorization': 'Bearer ' + token} }),
                fetch('/api/mac-cache', { headers: {'Authorization': 'Bearer ' + token} })
            ]);
            if (resSes.status === 401 || resMac.status === 401) {
                sessionStorage.removeItem('vpn_token');
                sessionStorage.removeItem('vpn_user');
                window.location.href = '/';
                return;
            }
            if (!resSes.ok || !resMac.ok) throw new Error('No se pudo obtener datos del backend.');

            const sesiones = await resSes.json();
            const macs = await resMac.json();
            let totalBytes = 0;
            let activas = 0;
            sesiones.forEach(s => {
                totalBytes += (s.bytes_enviados || 0) + (s.bytes_recibidos || 0);
                if (!s.timestamp_fin) activas += 1;
            });

            const nowObj = new Date();
            const nowLabel = nowObj.toLocaleTimeString();
            document.getElementById('total_transfer').textContent = fmtMB(totalBytes);
            document.getElementById('active_sessions').textContent = activas;
            document.getElementById('mac_count').textContent = macs.length;
            document.getElementById('last_update').textContent = 'Actualizado: ' + nowLabel + ' (cada 5s)';

            let mbps = 0;
            if (prevTs !== null) {
                const dt = (nowObj - prevTs) / 1000;
                const delta = Math.max(0, totalBytes - prevTotalBytes);
                if (dt > 0) mbps = (delta * 8) / (dt * 1000 * 1000);
            }
            document.getElementById('rate').textContent = mbps.toFixed(2) + ' Mbps';
            prevTotalBytes = totalBytes;
            prevTs = nowObj;
            document.getElementById('active_sessions').textContent = activas;
            document.getElementById('mac_count').textContent = macs.length;
            const cerradas = sesiones.length - activas;
            document.getElementById('kpi_mac').textContent = macs.length;
            document.getElementById('kpi_ses_total').textContent = sesiones.length;
            document.getElementById('kpi_ses_act').textContent = activas;
            document.getElementById('kpi_ses_cer').textContent = cerradas;

            if (trafficChart.data.labels.length > 20) {
                trafficChart.data.labels.shift();
                trafficChart.data.datasets[0].data.shift();
            }
            trafficChart.data.labels.push(nowLabel);
            trafficChart.data.datasets[0].data.push(Number((totalBytes / (1024 * 1024)).toFixed(2)));
            trafficChart.update('none');

            const devs = sesiones.slice(0, 2);
            const d1 = devs[0] || {};
            const d2 = devs[1] || {};
            function paintDevice(prefix, dev, fallbackName) {
                const tx = Number(dev.bytes_enviados || 0);
                const rx = Number(dev.bytes_recibidos || 0);
                const total = tx + rx;
                const name = dev.id_device ? ('PC-' + dev.id_device) : fallbackName;
                const online = dev.timestamp_fin ? 'disconnected' : 'connected';
                document.getElementById(prefix + '_name').textContent = name;
                document.getElementById(prefix + '_ip').textContent = dev.ip_publica_cliente || '-';
                document.getElementById(prefix + '_status').textContent = online;
                document.getElementById(prefix + '_tx').textContent = fmtMB(tx);
                document.getElementById(prefix + '_rx').textContent = fmtMB(rx);
                document.getElementById(prefix + '_total').textContent = fmtMB(total);
            }
            paintDevice('pc1', d1, 'PC-1');
            paintDevice('pc2', d2, 'PC-2');

            const macTable = document.getElementById('mac_table_body');
            macTable.innerHTML = macs.length === 0
                ? '<tr><td colspan="3">Sin datos</td></tr>'
                : macs.slice(0, 10).map(m =>
                    '<tr><td>' + m.mac_address + '</td><td>' + m.vport_addr + '</td><td>' + fmtDate(m.timestamp_ultimo_visto) + '</td></tr>'
                ).join('');

            const sesTable = document.getElementById('ses_table_body');
            sesTable.innerHTML = sesiones.length === 0
                ? '<tr><td colspan="5">Sin datos</td></tr>'
                : sesiones.map((s, idx) => {
                    const estado = s.timestamp_fin
                        ? '<span class="status-chip status-closed">Cerrada</span>'
                        : '<span class="status-chip status-open">Activa</span>';
                    return '<tr><td>' + (idx + 1) + '</td><td>' + s.ip_publica_cliente + '</td><td>' + fmtDate(s.timestamp_inicio) + '</td><td>' + fmtDate(s.timestamp_fin) + '</td><td>' + estado + '</td></tr>';
                }).join('');
        } catch (e) {
            console.error(e);
            errorBox.textContent = 'Error actualizando dashboard: ' + e.message;
        }
    }

    setInterval(cargarDatos, 5000);
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

@app.route("/registro")
def registro():
    return render_template_string(REGISTRO_HTML)

@app.route("/recuperar-password")
def recuperar_password_page():
    return render_template_string(RECUPERAR_HTML)

@app.route("/api/login", methods=["POST"])
def login():
    datos = request.json
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id_user, nombre_usuario, password_hash, activo FROM T_Usuarios WHERE nombre_usuario = %s",
                    (datos["nombre_usuario"],))
        usuario = cur.fetchone()
        if not usuario or not bcrypt.checkpw(datos["password"].encode(), usuario[2].encode()):
            return jsonify({"error": "Credenciales incorrectas"}), 401
        if not usuario[3]:
            return jsonify({"error": "Cuenta desactivada"}), 403

        expiracion = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        token = jwt.encode({"id_user": usuario[0], "exp": expiracion}, SECRET_KEY, algorithm="HS256")

        cur.execute("""INSERT INTO T_Tokens (id_user, token_string, fecha_expiracion)
                       VALUES (%s, %s, %s)""", (usuario[0], token, expiracion))
        db.commit()
        return jsonify({"token": token, "expira": expiracion.isoformat(), "nombre_usuario": usuario[1]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/registro", methods=["POST"])
def registrar_usuario():
    datos = request.json or {}
    nombre_usuario = (datos.get("nombre_usuario") or "").strip()
    email = (datos.get("email") or "").strip().lower()
    password = datos.get("password") or ""

    if not nombre_usuario or not email or not password:
        return jsonify({"error": "Todos los campos son obligatorios"}), 400

    # Validacion estricta para prevenir inyeccion SQL y XSS
    if not re.match(r"^[a-zA-Z0-9_.-]+$", nombre_usuario):
        return jsonify({"error": "Nombre de usuario inválido (solo letras, números, _ . -)"}), 400
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error": "Formato de correo electrónico inválido"}), 400

    if len(password) < 6:
        return jsonify({"error": "La contraseña debe tener al menos 6 caracteres"}), 400

    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("""SELECT nombre_usuario, email
                       FROM T_Usuarios
                       WHERE nombre_usuario = %s OR email = %s
                       LIMIT 1""",
                    (nombre_usuario, email))
        existente = cur.fetchone()
        if existente:
            if existente[0] == nombre_usuario and existente[1] == email:
                return jsonify({"error": "Ya existe una cuenta con ese nombre de usuario y correo"}), 409
            if existente[0] == nombre_usuario:
                return jsonify({"error": "El nombre de usuario ya está en uso"}), 409
            return jsonify({"error": "El correo ya está en uso"}), 409

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()
        cur.execute("""INSERT INTO T_Usuarios (nombre_usuario, password_hash, email)
                       VALUES (%s, %s, %s) RETURNING id_user""",
                    (nombre_usuario, password_hash, email))
        new_id = cur.fetchone()[0]
        db.commit()
        return jsonify({"ok": True, "id_user": new_id}), 201
    except psycopg2.errors.UniqueViolation:
        db.rollback()
        return jsonify({"error": "El usuario o correo ya existe"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/validar-usuario", methods=["POST"])
def validar_usuario_api():
    datos = request.json or {}
    nombre_usuario = (datos.get("nombre_usuario") or "").strip()
    email = (datos.get("email") or "").strip().lower()

    if not nombre_usuario or not email:
        return jsonify({"error": "Todos los campos son obligatorios"}), 400

    # Validacion de entrada antes de consultar la BD
    if not re.match(r"^[a-zA-Z0-9_.-]+$", nombre_usuario) or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error": "Formato de usuario o correo inválido"}), 400

    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id_user FROM T_Usuarios WHERE nombre_usuario = %s AND email = %s AND activo = TRUE",
                    (nombre_usuario, email))
        if cur.fetchone():
            return jsonify({"ok": True}), 200
        return jsonify({"error": "Usuario o correo incorrectos"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/recuperar-password", methods=["POST"])
def recuperar_password():
    datos = request.json or {}
    nombre_usuario = (datos.get("nombre_usuario") or "").strip()
    email = (datos.get("email") or "").strip().lower()
    nueva_password = datos.get("nueva_password") or ""

    if not nombre_usuario or not email or not nueva_password:
        return jsonify({"error": "Todos los campos son obligatorios"}), 400

    if not re.match(r"^[a-zA-Z0-9_.-]+$", nombre_usuario) or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error": "Formato de usuario o correo inválido"}), 400

    if len(nueva_password) < 8:
        return jsonify({"error": "La nueva contraseña debe tener al menos 8 caracteres"}), 400
    if not re.search(r"[A-Z]", nueva_password):
        return jsonify({"error": "La contraseña debe incluir al menos una letra mayúscula"}), 400
    if not re.search(r"[0-9]", nueva_password):
        return jsonify({"error": "La contraseña debe incluir al menos un número"}), 400
    if not re.search(r"[^A-Za-z0-9]", nueva_password):
        return jsonify({"error": "La contraseña debe incluir al menos un carácter especial"}), 400

    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("""SELECT id_user FROM T_Usuarios
                       WHERE nombre_usuario = %s AND email = %s AND activo = TRUE""",
                    (nombre_usuario, email))
        usuario = cur.fetchone()
        if not usuario:
            return jsonify({"error": "No coincide el usuario/correo"}), 404

        password_hash = bcrypt.hashpw(nueva_password.encode(), bcrypt.gensalt(12)).decode()
        cur.execute("UPDATE T_Usuarios SET password_hash = %s WHERE id_user = %s",
                    (password_hash, usuario[0]))
        db.commit()
        return jsonify({"ok": True}), 200
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
    cur.execute("""SELECT id_device, ip_publica_cliente::text, timestamp_inicio, timestamp_fin,
                          bytes_enviados, bytes_recibidos
                   FROM T_Sesiones
                   ORDER BY timestamp_inicio DESC LIMIT 20""")
    rows = cur.fetchall()
    return jsonify([{"id_device": r[0], "ip_publica_cliente": r[1],
                     "timestamp_inicio": r[2].isoformat(),
                     "timestamp_fin": r[3].isoformat() if r[3] else None,
                     "bytes_enviados": int(r[4] or 0),
                     "bytes_recibidos": int(r[5] or 0)} for r in rows])

from vswitch import iniciar_vswitch
iniciar_vswitch()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)