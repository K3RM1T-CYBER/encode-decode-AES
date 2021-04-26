import binascii
import os
import pbkdf2
import pyaes
import secrets


def genererCle():
    password = input("Choissisez une clé de chiffrement:\n")
    passwordSalt = os.urandom(16)
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    key = binascii.hexlify(key)
    return key


def chiffrement(key):
    iv = secrets.randbits(256)
    key = binascii.unhexlify(key)
    plaintext = input("Entrez le texte à chiffrer:\n")
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    ciphertext = aes.encrypt(plaintext)
    resultat = binascii.hexlify(ciphertext)
    return resultat, iv


def dechiffre(ciphertext, key, iv):
    ciphertext = binascii.unhexlify(ciphertext)
    key = bytes.fromhex(key)
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    decrypted = aes.decrypt(ciphertext)
    return decrypted


print("######################################")
print("#### CHIFFREMENT LUCAS GICQUEL AES ###")
print("######################################\n")

choixAction = int(input("Bonjour voulez vous chiffrer ou déchiffrer ?\n 1: Chiffrer \n 2: Déchiffrer\n"))

if choixAction == 1:
    cle = genererCle()
    messageChiffre, IV = chiffrement(cle)
    print("Voici votre message chiffré:")
    print(messageChiffre.decode("utf-8"))
    print("\nVoici votre clé")
    print(cle.decode("utf-8"))
    print("\nVoici votre IV")
    print(IV)

if choixAction == 2:
    ciphertext = input("Entrez votre message chiffré:\n")
    key = input("Entrez votre clé:\n")
    IV = int(input("Entrez votre IV:\n"))
    messageDechiffre = dechiffre(ciphertext, key, IV)
    print("\nVoici votre message déchiffré:")
    messageDechiffre = messageDechiffre.decode("utf-8")
    print(messageDechiffre)

else:
    exit(1)
