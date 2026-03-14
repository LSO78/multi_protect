from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Signature import pss
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256
import sys
import os

def get_dest_public_key_list(public_keys_dest_path: list) :
    list_key = []
    for key in public_keys_dest_path :
        with open(key, "r") as f:
            list_key.append(RSA.importKey(f.read()))
    return list_key

def get_key(key: str) -> bytes :
    with open(key, "r") as f:
        return RSA.importKey(f.read())

def get_kc() -> bytes :
    return get_random_bytes(32)

def get_iv() -> bytes :
    return get_random_bytes(16)

def data_encryption(kc: bytes, iv: bytes, file: bytes) -> bytes :
    cipher_object = AES.new(kc, AES.MODE_CBC, iv=iv)
    return cipher_object.encrypt(pad(file, AES.block_size))

def get_Wkc_iv(kc: bytes, iv: bytes, public_key_dest: bytes) -> bytes :
    kc_iv = kc + iv
    cipher = PKCS1_OAEP.new(public_key_dest)
    return cipher.encrypt(kc_iv)

def get_Wkc_iv_list(kc: bytes, iv: bytes, list_public_keys: list) -> bytes :
    wkc_iv_list = []
    for public_key in list_public_keys :
        wkc_iv = get_Wkc_iv(kc, iv, public_key)
        wkc_iv_list.append(wkc_iv)
    return wkc_iv_list

def hash_public_key(public_keys_dest: list) :
    hash_list = []
    for public_key in public_keys_dest :
        hash_list.append(SHA256.new((public_key).exportKey()).digest())
    return hash_list

def get_struct(hash_public_keys_dest: list, wkc_iv_list: list) -> bytes :
    debut = b'\x00'
    fin = b'\x01'
    struct = b''
    for hash, wkc_iv in zip(hash_public_keys_dest, wkc_iv_list) :
        struct += debut + hash + wkc_iv
    return struct + fin

def read_data_file(filename: str) -> bytes :
    with open(filename, "rb") as myfile :
        return myfile.read()

def RSA_sign(struct: bytes, encrypted_data: bytes, private_key: bytes) -> bytes :
    h = SHA256.new(struct)
    h.update(encrypted_data)
    return pss.new(private_key).sign(h)

def write_data_file(filename: str, struct: bytes, encrypted_data: bytes, sign: bytes) :
    with open(filename, "wb") as f :
        f.write(struct)
        f.write(encrypted_data)
        f.write(sign)

def get_data(file_in: str) :
    with open(file_in, "rb") as myfile:
        data = myfile.read()
        sign = data[-256:]
        i = 0
        while i < len(data) :
            if data[i] == 0x00 :
                i += 1 + 32 +256
                continue
            elif data[i] == 0x01 :
                struct = data[:i + 1]
                encrypted_data = data[i + 1:-256]
                break
            else :
                raise ValueError("[ERROR] Lecture de la structure impossible, l'index de fin (b'\\x01') n'est pas trouvé")
    return struct, encrypted_data, sign
            
def get_kc_iv(struct: bytes, my_ciph_priv: bytes, my_ciph_pub: bytes) :
    my_hash = SHA256.new(my_ciph_pub.exportKey()).digest()
    i = 0
    while i < len(struct) :
        hash = struct[i + 1:i + 33]
        if my_hash == hash :
           print("[INFO] Le message vous est bien attribué !")
           encrypted_kc_iv = struct[i + 33:i + 33 + 256]
           cipher = PKCS1_OAEP.new(my_ciph_priv)
           kc_iv = cipher.decrypt(encrypted_kc_iv)
           kc, iv = kc_iv[:32], kc_iv[32:]
           return kc, iv
        i += 1 + 32 + 256
    print("[ERROR] Le message ne vous est pas attribué !")

def verify_sign(struct: bytes, encrypted_data: bytes, file_in_sign: bytes, exp_sign_pub: bytes) -> bool :
    h = SHA256.new(struct)
    h.update(encrypted_data)
    try:
        pss.new(exp_sign_pub).verify(h, file_in_sign)
    except (ValueError, TypeError):
        raise ValueError("[ERROR] Signature invalide. Contrôle d'intégrité échoué")

def file_decryption(Kc: bytes, iv: bytes, data: bytes) -> bytes :
    cipher_object = AES.new(Kc, AES.MODE_CBC, iv=iv)
    decrypted_data = cipher_object.decrypt(data)
    return unpad(decrypted_data, AES.block_size)

def write_clear_file(filename: str, decrypted_data: bytes) :
    with open(filename, "wb") as f :
        f.write(decrypted_data)

def optimized_protect(kc: bytes, iv: bytes, struct: bytes, file_in: str, file_out: str, private_key: bytes) :
    cipher_object = AES.new(kc, AES.MODE_CBC, iv=iv)
    h = SHA256.new(struct)

    with open(file_in, "rb") as f1 :
        data = f1.read(AES.block_size)

        with open(file_out, "wb") as f2 :
            f2.write(struct)

            while len(data) > 0 :

                if len(data) < AES.block_size :
                    data = pad(data, AES.block_size)

                encrypted_data = cipher_object.encrypt(data)
                h.update(encrypted_data)
                f2.write(encrypted_data)
                data = f1.read(AES.block_size)

            if os.path.getsize(file_in) % AES.block_size == 0:
                padding_block = pad(b"", AES.block_size)
                encrypted_data = cipher_object.encrypt(padding_block)
                h.update(encrypted_data)
                f2.write(encrypted_data)

            f2.write(pss.new(private_key).sign(h))

def e(file_in: str, file_out: str, public_keys_dest_path: list, my_sign_priv: str ) :
    kc = get_kc()
    iv = get_iv()
    try:
        priv_key = get_key(my_sign_priv)
    except Exception as e:
        print(f"[ERROR] Impossible de charger la clé privée : {e}")
        sys.exit(1)
    dest_keys = get_dest_public_key_list(public_keys_dest_path)
    # data = read_data_file(file_in)
    # encrypted_data = data_encryption(kc, iv, data)
    wkc_iv_list = get_Wkc_iv_list(kc, iv, dest_keys)
    hash_pulic_key_list = hash_public_key(dest_keys)
    struct = get_struct(hash_pulic_key_list, wkc_iv_list)
    print(struct[0])
    # sign = RSA_sign(struct, encrypted_data, priv_key)
    # write_data_file(file_out, struct, encrypted_data, sign)
    optimized_protect(kc, iv, struct, file_in, file_out, priv_key)
    sys.exit(0)

def d(file_in: str, file_out: str, user_ciph_priv: str, user_ciph_pub: str, sender_sign_pub: str) :
    try:
        my_ciph_priv = get_key(user_ciph_priv)
        my_ciph_pub = get_key(user_ciph_pub)
        exp_sign_pub = get_key(sender_sign_pub)
    except Exception as e :
        print(f"[ERROR] Impossible de charger la clé : {e}")
        sys.exit(1)
    struct, encrypted_data, file_in_sign = get_data(file_in)
    kc, iv = get_kc_iv(struct, my_ciph_priv, my_ciph_pub)
    try:
        verify_sign(struct, encrypted_data, file_in_sign, exp_sign_pub)
        print("[INFO] Signature identique, vérification réussie")
    except ValueError as e:
        print(e)
        sys.exit(1)
    decrypt_data = file_decryption(kc, iv, encrypted_data)
    write_clear_file(file_out, decrypt_data)
    sys.exit(0)

def main():
    mode = sys.argv[1]

    if mode == "-e":
        file_in = sys.argv[2]
        file_out = sys.argv[3]
        my_sign_priv = sys.argv[4]
        public_keys_dest = sys.argv[5:]

        e(file_in, file_out, public_keys_dest, my_sign_priv)
    elif mode == "-d":
        file_in = sys.argv[2]
        file_out = sys.argv[3]
        user_ciph_priv = sys.argv[4]
        user_ciph_pub = sys.argv[5]
        my_sign_pub = sys.argv[6] 

        d(file_in, file_out, user_ciph_priv, user_ciph_pub, my_sign_pub)
    else:
        print("[ERROR] Mode invalide. Utilisez '-e' pour protéger ou '-d' pour déprotéger.")
        sys.exit(1)

main()
