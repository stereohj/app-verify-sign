# -*- coding: utf-8 -*-
"""
GEN_SIGN - Script simple para generación de firmas digitales

Expone un ejemplo de uso de primitivos de criptografía asimétrica para una aplicación con fines educativos.

Por: HJulian Mejia (@stereohj)
"""

# cryptography -> Módulo para manejo de funciones / algoritmos / métodos criptográficos
# * Documentación del módulo: https://cryptography.io/en/latest/

# * Módulos de "cryptography"
from cryptography.hazmat.primitives.asymmetric import rsa       # Entorno de algoritmo RSA
from cryptography.hazmat.primitives.asymmetric import padding   # Entorno de algoritmo RSA - Esquemas de padding
from cryptography.hazmat.primitives import serialization        # Entorno de serialización ("codificación")
from cryptography.hazmat.primitives import hashes               # Entorno de funciones resumen (hash)


# ---- Funciones ---- #


def gen_rsa_keys(pub_exp: int = 65537, 
                 key_len: int = 2048) -> tuple: 
    
    """Generates a RSA key pair

    Args:
        pub_exp (int, optional): The public exponent of the new key. Defaults to `65537`.
        key_len (int, optional): The length of the modulus in bits. Defaults to `2048`.

    Returns:
        tuple: The RSA key pair `(RSAPrivateKey, RSAPublicKey)` object.
    """
    
    # Generar componente privado
    priv_key = rsa.generate_private_key(public_exponent = pub_exp, 
                                        key_size = key_len)

    # Generar componente público
    # * NOTA: El objeto previo retornado de tipo "RSAPrivateKey" contiene "inmerso"
    # * el componente público de tipo "RSAPublicKey". 
    pub_key = priv_key.public_key()

    return priv_key, pub_key

# ------------------------------------------------------------------------------------------ #

def rsa_key_to_pem(priv_key: rsa.RSAPrivateKey = None, 
                      pub_key: rsa.RSAPublicKey = None) -> tuple:
    
    """Generates PEM formatted strings of private or public RSA keys under PKCS#1 notation.

    Args:
        priv_key (rsa.RSAPrivateKey): Private Key object.
        pub_key (rsa.RSAPublicKey): Public Key object.

    Returns:
        tuple: Private and Public key PEM formatted strings.
        
        NOTE: If some of key parameters is `None` this value will be assigned to corresponding tuple position.
    """

    if(priv_key != None):
        # ! NOTA: En un entorno real y para efectos de importación SE DEBE CIFRAR el componente privado. 
        # ! Dada la finalidad educativa de este contexto, no se cifra (objeto "NoEncrption").
        pem_priv_key = priv_key.private_bytes(encoding = serialization.Encoding.PEM,
                                            format = serialization.PrivateFormat.TraditionalOpenSSL,
                                            encryption_algorithm = serialization.NoEncryption()).decode()
        
    if(pub_key != None):                      
        pem_pub_key = pub_key.public_bytes(encoding = serialization.Encoding.PEM,
                                        format = serialization.PublicFormat.PKCS1).decode()
    
    return pem_priv_key, pem_pub_key

# ------------------------------------------------------------------------------------------ #

def gen_sha2(message: bytes, to_bytes: bool = False) -> str | bytes:
    

    """Generate a SHA-256 digest.

    Args:
        message (bytes): Data to be hashed.
        to_bytes (bool): Data digest returned as a `bytes` object. Defaults to `False`.

    Returns:
        str | bytes: The 256-bits Hex string digest of the data.
    """
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    
    if(to_bytes):
        return digest.finalize()
    else:
        return digest.finalize().hex()

# ------------------------------------------------------------------------------------------ #

def enc_rsa(pub_key: rsa.RSAPublicKey | str, plaintext: bytes) -> bytes:
    """_summary_

    Args:
        pub_key (rsa.RSAPublicKey | str): `RSAPublicKey` public key object or the corresponding PEM encoding string.
        NOTE: Can be the PATH file to PEM file. 
        plaintext (bytes): Message to be encrypted.

    Returns:
        bytes: Returned ciphertext.
    """
    
    # TODO: Tratamiento de llave pública como tipo str (información PEM explícita o RUTA al "archivo PEM" respectivo)
    
    ciphertext = pub_key.encrypt(plaintext, 
                                padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None)
                                )

    return ciphertext