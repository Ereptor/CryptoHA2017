import random
from Crypto.Protocol import KDF


def get_chain_and_message_key(password):
    salt = ''.join(random.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz') for i in range(32))
    kdf = KDF.PBKDF2(password, salt, 32)
    chain_key=kdf[:16]
    message_key=kdf[16:]
    return chain_key, message_key