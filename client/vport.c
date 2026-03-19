#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define TAP_NAME     "tapyuan"
#define BUF_SIZE     4096
#define IV_LEN       12
#define TAG_LEN      16
#define MAX_PKT      (BUF_SIZE + IV_LEN + TAG_LEN)

/* ── Variables globales ─────────────────────────────── */
static unsigned char session_key[32];   /* AES-256 → 32 bytes */
static int           authenticated = 0;

/* ── Abrir dispositivo TAP ──────────────────────────── */
int tap_open(const char *name) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open /dev/net/tun"); exit(1); }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl TUNSETIFF"); close(fd); exit(1);
    }
    printf("[TAP] Interfaz %s abierta\n", name);
    return fd;
}

/* ── Crear socket UDP ───────────────────────────────── */
int udp_socket(const char *server_ip, int port, struct sockaddr_in *srv) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); exit(1); }

    memset(srv, 0, sizeof(*srv));
    srv->sin_family      = AF_INET;
    srv->sin_port        = htons(port);
    srv->sin_addr.s_addr = inet_addr(server_ip);
    return fd;
}

/* ── Derivar clave AES-256 desde token (HKDF-SHA256) ── */
void derivar_clave(const char *token) {
    /* Usamos SHA-256 del token como clave de sesión         */
    /* (simplificado — en producción usar HKDF completo)    */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len = 32;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, token, strlen(token));
    EVP_DigestUpdate(ctx, "vpn-l2-session", 14);
    EVP_DigestFinal_ex(ctx, session_key, &len);
    EVP_MD_CTX_free(ctx);
}

/* ── Cifrar con AES-256-GCM ─────────────────────────── */
/* Formato salida: IV(12) + CIPHERTEXT + TAG(16)         */
int cifrar(const unsigned char *plain, int plain_len,
           unsigned char *out) {
    unsigned char iv[IV_LEN];
    RAND_bytes(iv, IV_LEN);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, out_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, session_key, iv);
    EVP_EncryptUpdate(ctx, out + IV_LEN, &len, plain, plain_len);
    out_len = len;
    EVP_EncryptFinal_ex(ctx, out + IV_LEN + out_len, &len);
    out_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN,
                        out + IV_LEN + out_len);
    EVP_CIPHER_CTX_free(ctx);

    memcpy(out, iv, IV_LEN);
    return IV_LEN + out_len + TAG_LEN;
}

/* ── Descifrar con AES-256-GCM ──────────────────────── */
/* Retorna longitud del plaintext o -1 si falla          */
int descifrar(const unsigned char *in, int in_len,
              unsigned char *plain) {
    if (in_len < IV_LEN + TAG_LEN) return -1;

    const unsigned char *iv         = in;
    const unsigned char *ciphertext = in + IV_LEN;
    int cipher_len = in_len - IV_LEN - TAG_LEN;
    const unsigned char *tag = in + IV_LEN + cipher_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ret;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, session_key, iv);
    EVP_DecryptUpdate(ctx, plain, &len, ciphertext, cipher_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                        (void *)tag);
    ret = EVP_DecryptFinal_ex(ctx, plain + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) return -1;   /* TAG inválido → descartar */
    return cipher_len;
}

/* ── Handshake JWT con el VSwitch ───────────────────── */
int handshake(int udp_fd, struct sockaddr_in *srv,
              const char *token) {
    char resp[32] = {0};
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);

    printf("[AUTH] Enviando token JWT al VSwitch...\n");
    sendto(udp_fd, token, strlen(token), 0,
           (struct sockaddr *)srv, sizeof(*srv));

    /* Esperar AUTH_OK o AUTH_FAIL */
    int n = recvfrom(udp_fd, resp, sizeof(resp)-1, 0,
                     (struct sockaddr *)&from, &from_len);
    if (n <= 0) { perror("recvfrom handshake"); return -1; }
    resp[n] = '\0';

    if (strcmp(resp, "AUTH_OK") == 0) {
        printf("[AUTH] Autenticado correctamente\n");
        derivar_clave(token);
        return 0;
    }
    printf("[AUTH] Autenticacion fallida: %s\n", resp);
    return -1;
}

/* ── Main ───────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Uso: %s <SERVER_IP> <PORT> <JWT_TOKEN>\n",
                argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];
    int         port      = atoi(argv[2]);
    const char *token     = argv[3];

    struct sockaddr_in srv;
    int tap_fd = tap_open(TAP_NAME);
    int udp_fd = udp_socket(server_ip, port, &srv);

    /* Handshake JWT */
    if (handshake(udp_fd, &srv, token) < 0) {
        fprintf(stderr, "[ERROR] No se pudo autenticar\n");
        return 1;
    }

    printf("[VPort] Listo — reenviando tramas cifradas\n");

    unsigned char buf[BUF_SIZE];
    unsigned char pkt[MAX_PKT];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    fd_set fds;

    while (1) {
        FD_ZERO(&fds);
        FD_SET(tap_fd, &fds);
        FD_SET(udp_fd, &fds);
        int maxfd = (tap_fd > udp_fd ? tap_fd : udp_fd) + 1;

        if (select(maxfd, &fds, NULL, NULL, NULL) < 0) break;

        /* TAP → cifrar → UDP */
        if (FD_ISSET(tap_fd, &fds)) {
            int n = read(tap_fd, buf, BUF_SIZE);
            if (n <= 0) continue;
            int enc_len = cifrar(buf, n, pkt);
            sendto(udp_fd, pkt, enc_len, 0,
                   (struct sockaddr *)&srv, sizeof(srv));
        }

        /* UDP → descifrar → TAP */
        if (FD_ISSET(udp_fd, &fds)) {
            int n = recvfrom(udp_fd, pkt, MAX_PKT, 0,
                             (struct sockaddr *)&from, &from_len);
            if (n <= 0) continue;
            int dec_len = descifrar(pkt, n, buf);
            if (dec_len < 0) {
                printf("[SEC] Paquete invalido descartado\n");
                continue;
            }
            write(tap_fd, buf, dec_len);
        }
    }

    close(tap_fd);
    close(udp_fd);
    return 0;
}