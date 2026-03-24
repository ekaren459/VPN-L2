import socket
import os
import jwt
import psycopg2
import threading
import time
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_PORT = int(os.environ.get("VSWITCH_PORT", 8888))
JWT_SECRET  = os.environ.get("JWT_SECRET", "mi_clave_secreta_super_segura_2024")
DB_HOST     = os.environ.get("DB_HOST", "database")
DB_NAME     = os.environ.get("DB_NAME", "vpnl2")
DB_USER     = os.environ.get("DB_USER", "vpnuser")
DB_PASS     = os.environ.get("DB_PASS", "vpnpass")

mac_table  = {}
vport_keys = {}
vport_last_seen = {}
vport_sesiones = {}
TIMEOUT_SEGUNDOS = 30  # 30 segundos de inactividad para cerrar

def get_db():
    return psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)

def derivar_clave(token_string):
    return hashlib.sha256(token_string.encode() + b"vpn-l2-session").digest()

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
    except Exception as e:
        pass

def registrar_sesion(id_user, id_token, ip_cliente):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id_device FROM T_Dispositivos WHERE id_user = %s LIMIT 1", (id_user,))
        dev = cur.fetchone()
        
        if not dev:
            mac_virtual = f"02:00:00:00:00:{id_user:02x}"
            cur.execute("""
                INSERT INTO T_Dispositivos (id_user, mac_address, nombre_dispositivo) 
                VALUES (%s, %s, %s) RETURNING id_device
            """, (id_user, mac_virtual, f"VPort-{ip_cliente}"))
            id_device = cur.fetchone()[0]
        else:
            id_device = dev[0]
            
        cur.execute("""
            INSERT INTO T_Sesiones (id_device, id_token, ip_publica_cliente, server_node)
            VALUES (%s, %s, %s, 'VSwitch-Principal') RETURNING id_sesion
        """, (id_device, id_token, ip_cliente))
        
        id_sesion = cur.fetchone()[0]
        db.commit()
        db.close()
        print(f"[SESION] Iniciada sesion {id_sesion} desde {ip_cliente}")
        return id_sesion
    except Exception as e:
        print(f"[DB] Error registrando sesion: {e}")
        return None

def autenticar(data, addr):
    try:
        token_str = data.decode().strip()
        payload = jwt.decode(token_str, JWT_SECRET, algorithms=["HS256"])
        
        db  = get_db()
        cur = db.cursor()
        cur.execute("""
            SELECT id_token, revocado FROM T_Tokens
            WHERE token_string = %s AND fecha_expiracion > NOW()
        """, (token_str,))
        row = cur.fetchone()
        db.close()
        
        if not row or row[1]:
            return None
            
        clave = derivar_clave(token_str)
        vport_keys[addr] = clave
        print(f"[AUTH] VPort AUTENTICADO: {addr}")
        
        id_ses = registrar_sesion(payload['id_user'], row[0], addr[0])
        if id_ses:
            vport_sesiones[addr] = id_ses
            vport_last_seen[addr] = time.time()
            
        return clave
    except Exception as e:
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
            
            # Refrescar el tiempo del VPort
            if addr in vport_last_seen:
                vport_last_seen[addr] = time.time()

            if addr not in vport_keys:
                clave = autenticar(data, addr)
                sock.sendto(b"AUTH_OK" if clave else b"AUTH_FAIL", addr)
                continue

            clave = vport_keys[addr]
            trama = descifrar(clave, data)
            
            if trama is None or len(trama) < 12:
                continue

            mac_dst = trama[0:6]
            mac_src = trama[6:12]
            mac_src_str = ":".join(f"{b:02x}" for b in mac_src)
            mac_dst_str = ":".join(f"{b:02x}" for b in mac_dst)

            if mac_src_str not in mac_table:
                mac_table[mac_src_str] = (addr, clave)
                upsert_mac(mac_src_str, addr)
                # print(f"[MAC] Aprendida {mac_src_str} -> {addr}")

            broadcast = all(b == 0xff for b in mac_dst)
            if broadcast or mac_dst_str not in mac_table:
                for peer_addr, peer_clave in list(vport_keys.items()):
                    if peer_addr != addr:
                        sock.sendto(cifrar(peer_clave, trama), peer_addr)
            else:
                dst_addr, dst_clave = mac_table[mac_dst_str]
                sock.sendto(cifrar(dst_clave, trama), dst_addr)

        except Exception as e:
            continue

def hilo_limpiador():
    print("[CLEANUP] Hilo limpiador iniciado y vigilando...")
    while True:
        try:
            time.sleep(10)
            ahora = time.time()
            desconectados = []

            for addr, ultimo_visto in list(vport_last_seen.items()):
                if (ahora - ultimo_visto) > TIMEOUT_SEGUNDOS:
                    desconectados.append(addr)

            if desconectados:
                db = get_db()
                cur = db.cursor()
                for addr in desconectados:
                    id_sesion = vport_sesiones.get(addr)
                    if id_sesion:
                        # MARCAMOS EL FIN EN LA BD
                        cur.execute("UPDATE T_Sesiones SET timestamp_fin = NOW() WHERE id_sesion = %s", (id_sesion,))
                        print(f"[SESION] Timeout detectado. Sesion {id_sesion} del VPort {addr} CERRADA.")
                    
                    # Limpiamos RAM
                    vport_keys.pop(addr, None)
                    vport_last_seen.pop(addr, None)
                    vport_sesiones.pop(addr, None)
                    
                    # Limpiamos MACs en RAM
                    macs_a_borrar = [mac for mac, data in list(mac_table.items()) if data[0] == addr]
                    for m in macs_a_borrar:
                        mac_table.pop(m, None)

                # Limpiamos las MACs viejas en BD
                cur.execute("DELETE FROM T_Mac_Cache WHERE timestamp_ultimo_visto < NOW() - INTERVAL '2 minutes'")
                db.commit()
                db.close()
        except Exception as e:
            print(f"[CLEANUP] Error critico en el hilo limpiador: {e}")

def iniciar_vswitch():
    t1 = threading.Thread(target=vswitch_loop, daemon=True)
    t1.start()
    t2 = threading.Thread(target=hilo_limpiador, daemon=True)
    t2.start()
    print("[VSwitch] Ambos hilos iniciados")