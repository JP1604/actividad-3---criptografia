"""
atacante.py — Servidor del atacante (Modelo B)
Simulación de ransomware — Taller 3 Criptografía

Ejecución:
  1. Abrir terminal → python atacante.py
  2. Luego en otra terminal → python victima.py
"""

import json, base64, socket, time
from Crypto.Util import number

# ─────────────────────── Config ───────────────────────
IP   = '127.0.0.1'
PORT = 9999
KL   = 32   # tamaño de la clave simétrica en bytes (256 bits)

# ─────────────────────── RSA-CRT ──────────────────────
class MyRSACRT:
    def Grsa(self, l, e):
        """Genera par de llaves RSA con CRT."""
        p = number.getPrime(l)
        while number.GCD(p - 1, e) != 1:
            p = number.getPrime(l)
        q = number.getPrime(l)
        while number.GCD(q - 1, e) != 1 or p == q:
            q = number.getPrime(l)

        phi  = (p - 1) * (q - 1)
        d    = number.inverse(e, phi)
        n    = p * q
        pk   = (n, e)
        dp   = d % (p - 1)
        dq   = d % (q - 1)
        qinv = number.inverse(q, p)
        sk   = (p, q, dp, dq, qinv)
        return sk, pk

    def Frsa(self, pk, x):
        """Cifrado RSA: c = x^e mod n."""
        n, e = pk
        return pow(x, e, n)

    def Irsa(self, sk, y):
        """Descifrado RSA con CRT."""
        p, q, dp, dq, qinv = sk
        xp = pow(y, dp, p)
        xq = pow(y, dq, q)
        h  = qinv * (xp - xq) % p
        return xq + q * h

# ─────────────────── Utilidades de red ─────────────────
def recibir_completo(conn, n):
    buf = b''
    while len(buf) < n:
        t = conn.recv(n - len(buf))
        if not t:
            raise ConnectionError("Conexión cerrada inesperadamente")
        buf += t
    return buf

def mandar_json(conn, d):
    m = json.dumps(d).encode()
    conn.sendall(len(m).to_bytes(4, 'big') + m)

def leer_json(conn):
    n = int.from_bytes(recibir_completo(conn, 4), 'big')
    return json.loads(recibir_completo(conn, n).decode())

# ─────────────────── FASE 1: Cifrado ──────────────────
def fase1_cifrado(rsa, sk, pk):
    """
    El atacante espera la conexión de la víctima,
    le envía la clave pública, recibe c = FRSA(pk, Ksym),
    y descifra Ksym usando su clave privada.
    """
    n, e = pk
    print(f"\n[Atacante] Esperando conexión de la víctima en {IP}:{PORT}...")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((IP, PORT))
    srv.listen(1)

    conn, addr = srv.accept()
    print(f"[Atacante] >> Víctima conectada desde: {addr}")

    with conn:
        # Enviar clave pública
        mandar_json(conn, {'tipo': 'pk', 'n': n, 'e': e})
        print(f"[Atacante] Llave pública enviada (tamaño n: {n.bit_length()} bits)")

        # Recibir ciphertext c
        msg = leer_json(conn)
        c = msg['c']

        # Descifrar Ksym
        ksym_int = rsa.Irsa(sk, c)
        ksym = ksym_int.to_bytes(KL, 'big')
        print(f"[Atacante] Clave Ksym interceptada y descifrada: {ksym.hex()[:16]}...")

        conn.sendall(b'OK\x00\x00')

    srv.close()
    return ksym

# ─────────────────── FASE 2: Recuperación ─────────────
def fase2_recuperacion(ksym):
    """
    El atacante espera que la víctima reconecte (simulando
    que ya se realizó el pago) y le envía la Ksym.
    """
    print(f"\n[Atacante] Abriendo servidor de rescate en {IP}:{PORT}...")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((IP, PORT))
    srv.listen(1)

    conn, _ = srv.accept()
    with conn:
        mandar_json(conn, {
            'tipo': 'recuperacion',
            'ksym': base64.b64encode(ksym).decode()
        })
        print("[Atacante] Clave enviada a la víctima tras el 'pago'")

        ack = conn.recv(16)
        if b'OK' in ack:
            print("[Atacante] Operación confirmada por la víctima")

    srv.close()

# ─────────────────── Main ─────────────────────────────
def main():
    rsa = MyRSACRT()

    print("=" * 50)
    print("   ATACANTE — Simulación Ransomware (Modelo B)")
    print("=" * 50)
    print("\n[Config] Generando par de llaves RSA 512 bits...")
    sk, pk = rsa.Grsa(512, 65537)
    print("[Config] Llaves generadas exitosamente.")

    # ── Fase 1 ──
    print("\n" + "=" * 40)
    print("  FASE 1: ATAQUE Y CIFRADO")
    print("=" * 40)
    ksym = fase1_cifrado(rsa, sk, pk)

    # ── Esperar para fase 2 ──
    print("\n" + "-" * 40)
    input("[Atacante] Presione ENTER para iniciar la fase de recuperación...")

    # ── Fase 2 ──
    print("\n" + "=" * 40)
    print("  FASE 2: PAGO Y RECUPERACIÓN")
    print("=" * 40)
    fase2_recuperacion(ksym)

    print("\n*** ATACANTE: SIMULACIÓN TERMINADA ***\n")

if __name__ == '__main__':
    main()