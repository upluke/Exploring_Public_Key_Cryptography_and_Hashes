from Crypto.Util import number
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
def rsa():
    e = 65537
    num_bits = 2048
    p = number.getPrime(num_bits)
    q = number.getPrime(num_bits)
    n = p * q
    lambda_n = lcm(p-1, q-1)
    _, x, _ = extended_gcd(e, lambda_n)
    d = x % lambda_n
    
    return n, e, d

def lcm(a: int, b: int):
    return abs(a * b) // gcd(a, b)

def gcd(a: int, b: int):
    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a: int, b: int):  
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = divmod(b, a)
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    return gcd, x, y

def mallory_attack(n, e: int= 65537):        
    c_prime = pow(c, 2, n)  
    
    return c_prime
     

def alice_protocol():
    n, e, d = rsa()    
    return n, e, d

def bob_protocol(n, e):
    s = number.getRandomRange(1, n-1)
    c = pow(s, e, n)
    
    return c, s

def mallory_protocol(c):
    c_prime = mallory_attack(c)
    
    return c_prime

def alice_decrypt(n, d, c_prime):
    s = pow(c_prime, d, n)
    aes_key = SHA256.new(str(s).encode()).digest()
    plaintext = b"Hi Bob!" 
    padded_plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(aes_key, AES.MODE_CBC, b'1234567890123456')  
    ciphertext = cipher.encrypt(padded_plaintext)
    print("Alice sends encrypted message to Bob:", ciphertext.hex())


n, e, d = alice_protocol()

c, s = bob_protocol(n, e)

# Mallory performs the attack and manipulates the ciphertext
c_prime = mallory_protocol(c)

# Alice decrypts the manipulated ciphertext to get the AES-CBC encrypted message
alice_decrypt(n, d, c_prime)
