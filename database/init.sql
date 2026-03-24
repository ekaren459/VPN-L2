-- VPN L2 - Base de datos completa en 3FN

CREATE TABLE T_Usuarios (
    id_user          SERIAL PRIMARY KEY,
    nombre_usuario   VARCHAR(50)  UNIQUE NOT NULL,
    password_hash    VARCHAR(60)  NOT NULL, -- FIX: Cambiado a VARCHAR para no corromper el hash
    email            VARCHAR(100) UNIQUE NOT NULL,
    fecha_creacion   TIMESTAMP    NOT NULL DEFAULT NOW(),
    activo           BOOLEAN      NOT NULL DEFAULT TRUE
);

CREATE TABLE T_Dispositivos (
    id_device          SERIAL PRIMARY KEY,
    id_user            INTEGER     NOT NULL REFERENCES T_Usuarios(id_user) ON DELETE CASCADE,
    mac_address        CHAR(17)    UNIQUE NOT NULL,
    nombre_dispositivo VARCHAR(50) NOT NULL,
    fecha_registro     TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE TABLE T_Tokens (
    id_token         SERIAL PRIMARY KEY,
    id_user          INTEGER   NOT NULL REFERENCES T_Usuarios(id_user) ON DELETE CASCADE,
    token_string     TEXT      NOT NULL,
    fecha_emision    TIMESTAMP NOT NULL DEFAULT NOW(),
    fecha_expiracion TIMESTAMP NOT NULL,
    revocado         BOOLEAN   NOT NULL DEFAULT FALSE
);

CREATE TABLE T_Sesiones (
    id_sesion          SERIAL PRIMARY KEY,
    id_device          INTEGER     NOT NULL REFERENCES T_Dispositivos(id_device),
    id_token           INTEGER     NOT NULL REFERENCES T_Tokens(id_token),
    timestamp_inicio   TIMESTAMP   NOT NULL DEFAULT NOW(),
    timestamp_fin      TIMESTAMP,
    ip_publica_cliente INET        NOT NULL,
    server_node        VARCHAR(50) NOT NULL,
    bytes_enviados     BIGINT      NOT NULL DEFAULT 0,
    bytes_recibidos    BIGINT      NOT NULL DEFAULT 0
);

CREATE TABLE T_Mac_Cache (
    id_cache               SERIAL   PRIMARY KEY,
    mac_address            CHAR(17) UNIQUE NOT NULL,
    vport_addr             VARCHAR(50) NOT NULL,
    timestamp_ultimo_visto TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mac_cache_mac ON T_Mac_Cache(mac_address);

-- Usuario de prueba (password: admin123)
-- FIX: Hash bcrypt real inyectado directamente
-- Usuario de prueba (password: admin123)
-- FIX: Hash bcrypt real inyectado directamente y verificado
INSERT INTO T_Usuarios (nombre_usuario, password_hash, email)
VALUES ('admin', '$2b$12$BEr6oeSX1fUqiIJ/cNqCIOsM1/XSTNgOWwAZeGb9Dh.KOeZIyYmWy', 'admin@vpnl2.local');