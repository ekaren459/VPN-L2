import socket
import os
import jwt
import psycopg2
import threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

SERVER_PORT = int(os.environ.get("VSWITCH_PORT", 8888))
JWT_SECRET  = os.environ.get("JWT_SECRET", "mi_clave_secreta_super_segura_2024")
DB_HOST     = os.environ.get("DB_HOST", "database")
DB_NAME     = os.environ.get("DB_NAME", "vpnl2")
DB_USER     = os.environ.get("DB_USER", "vpnuser")
DB_PASS     = os.environ.get("DB_PASS", "vpnpass")

mac_table  = {}
vport_keys = {}

def get_db():
    return psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)

def derivar_clave(token_string):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"vpn-l2-session")
    return hkdf.derive(token_string.encode())

def cifrar(clave, trama):
    iv = os.urandom(12)
    return iv + AESGCM(clave).encrypt(iv, trama, None)

def descifrar(clave, datos):
    try:
        return AESGCM(clave).decrypt(datos[:12], datos[12:], None)
    except Exception:
        return None

def upsert_mac(mac, addr):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("""
            INSERT INTO T_Mac_Cache (mac_address, vport_addr)
            VALUES (%s, %s)
            ON CONFLICT (mac_address) DO UPDATE
              SET vport_addr = EXCLUDED.vport_addr,
                  timestamp_ultimo_visto = NOW()
        """, (mac, f"{addr[0]}:{addr[1]}"))
        db.commit()
        db.close()
        print(f"[DB] MAC guardada: {mac} → {addr[0]}:{addr[1]}")
    except Exception as e:
        print(f"[DB] Error upsert MAC: {type(e).__name__}: {e}")

def autenticar(data, addr):
    try:
        token_str = data.decode().strip()
        print(f"[AUTH] Token recibido de {addr}: {token_str[:30]}...")
        payload = jwt.decode(token_str, JWT_SECRET, algorithms=["HS256"])
        print(f"[AUTH] JWT valido, usuario {payload['id_user']}")
        db  = get_db()
        cur = db.cursor()
        cur.execute("""
            SELECT id_token, revocado FROM T_Tokens
            WHERE token_string = %s AND fecha_expiracion > NOW()
        """, (token_str,))
        row = cur.fetchone()
        db.close()
        if not row:
            print(f"[AUTH] Token NO encontrado en BD desde {addr}")
            return None
        if row[1]:
            print(f"[AUTH] Token REVOCADO desde {addr}")
            return None
        clave = derivar_clave(token_str)
        vport_keys[addr] = clave
        print(f"[AUTH] VPort AUTENTICADO: {addr} usuario {payload['id_user']}")
        return clave
    except jwt.ExpiredSignatureError:
        print(f"[AUTH] Token EXPIRADO desde {addr}")
        return None
    except Exception as e:
        print(f"[AUTH] ERROR: {type(e).__name__}: {e}")
        return None

def vswitch_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", SERVER_PORT))
    sock.setblocking(True)
    print(f"[VSwitch] Iniciado en 0.0.0.0:{SERVER_PORT} — AES-256-GCM activo")

    while True:
        try:
            data, addr = sock.recvfrom(65536)
            print(f"[VSwitch] Paquete recibido de {addr}, tamaño {len(data)}")

            if addr not in vport_keys:
                clave = autenticar(data, addr)
                sock.sendto(b"AUTH_OK" if clave else b"AUTH_FAIL", addr)
                continue

            clave = vport_keys[addr]
            trama = descifrar(clave, data)
            
            if trama is None:
               print(f"[VSwitch] Descifrado fallido de {addr}")
               continue
            if len(trama) < 12:
             print(f"[VSwitch] Trama muy corta: {len(trama)} bytes de {addr}")
             continue

            

            mac_dst = trama[0:6]
            mac_src = trama[6:12]
            mac_src_str = ":".join(f"{b:02x}" for b in mac_src)
            mac_dst_str = ":".join(f"{b:02x}" for b in mac_dst)

            if mac_src_str not in mac_table:
                mac_table[mac_src_str] = (addr, clave)
                upsert_mac(mac_src_str, addr)
                print(f"[MAC] Aprendida {mac_src_str} → {addr}")

            broadcast = all(b == 0xff for b in mac_dst)
            if broadcast or mac_dst_str not in mac_table:
                for peer_addr, peer_clave in list(vport_keys.items()):
                    if peer_addr != addr:
                        sock.sendto(cifrar(peer_clave, trama), peer_addr)
            else:
                dst_addr, dst_clave = mac_table[mac_dst_str]
                sock.sendto(cifrar(dst_clave, trama), dst_addr)

        except Exception as e:
            print(f"[VSwitch] Error en loop: {e}")
            continue

def iniciar_vswitch():
    t = threading.Thread(target=vswitch_loop, daemon=True)
    t.start()
    print("[VSwitch] Hilo iniciado correctamente")
