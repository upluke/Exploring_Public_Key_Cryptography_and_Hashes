from Crypto.Cipher import AES
from hashlib import sha256
import random
import urllib.parse

from Crypto.Util.Padding import pad, unpad

 

# Purpose of Diffie-Hellman key exchange algorithm is 
# exchanging public keys and calculate secret keys using public keys.
# Then subsequent mesgs (further communications) are encrypted using secret keys.
def dhp(p: int, g: int, m_alice: str, m_bob: str):
    
   alice_prviate_key = random.randint(2,p-1)  # ℤp 
   alice_public_key = pow(g, alice_prviate_key, p) # g^a % p
   
   bob_private_key = random.randint(2,p-1)
   bob_public_key = pow(g, bob_private_key, p)
   
   # a, b = private key
   # A = alice_public_key
   # B = bob_public_key
   # s = shared secret = B^a mod p 
   # k = secret key (can't get s from k, but if have s, we can get k)
   
   s_alice = pow(bob_public_key, alice_prviate_key, p) 
   s_bob = pow(alice_public_key, bob_private_key, p)   
   # print( s_Alice, s_Bob)
   
   
   k_alice = sha256((s_alice).to_bytes(128, 'big')).digest() 
   k_alice = k_alice[:16]
   
   k_bob = sha256((s_bob).to_bytes(128, "big")).digest()
   k_bob = k_bob[:16]
   
   
   m_alice_bytes = pad(m_alice.encode(), 16)
   
   
   m_bob_bytes = pad(m_bob.encode(), 16)
   
   # make encryptor objects
   encryptor_alice = AES.new(k_alice, AES.MODE_CBC, iv=k_alice) # type: ignore
   encryptor_bob = AES.new(k_bob, AES.MODE_CBC, iv=k_bob)
   
   decryptor_alice = AES.new(k_alice, AES.MODE_CBC, iv=k_alice)
   decryptor_bob = AES.new(k_bob, AES.MODE_CBC, iv=k_bob)
   
   ctext_bob = encryptor_bob.encrypt(m_bob_bytes)
   m_alice_received = unpad(decryptor_alice.decrypt(ctext_bob), 16)
  
   ctext_alice = encryptor_alice.encrypt(m_alice_bytes)
   m_bob_received = unpad(decryptor_bob.decrypt(ctext_alice), 16) 
   
   
   print("Bob received: ", m_bob_received.decode())
   print("Alice received: ", m_alice_received.decode()) 



# g = 5
# p = 37



   

"""
Alice: 
pick a = 8    # lower a and b are private keys
a = secret key
A = public key
A = g^a % p
    = 5^8 % 37     # pow(5, 8, 37)
    =16 
                       Bob picks a secret key b=?
                       Bob calculats B = 18, and gives to Alice

s = shared secret 
s = B^a % p
   = 18 ^ 8 % 37
   =12

k will be used to encode a msg  
>>> from hashlib import sha256
>>> sha256((12).to_bytes(4, 'little')).hexdigest()
'42f4aeb81c1ef81f771f3de8abca9dcf66901c575530e7672e4b1146474ae650'


P big prime 
g primitive root 
"""




if __name__ == "__main__":
   g ="""A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
   D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
   160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
   909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
   D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
   855E6EEB 22B3B2E5"""

   p ="""B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
   9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
   13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
   98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
   A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
   DF1FB2BC 2E4A4371"""


   g = int(g.replace(" ", "").replace("\n", ""), 16)
   p = int(p.replace(" ", "").replace("\n", ""), 16) 
   m_alice = "Hello wolrd!"
   m_bob = "No thanks!"
   dhp(p, g, m_alice, m_bob)



# MITM in Diffie-Hellman key exchange takes palce during exchanges of public keys,
# it may be attacker capture the both keys and nwe values of keys
# are share with both the users. Subsequent encrypted msgs are red and modified by 
# attacker. Then send to the respective user. Using this attack attacker may read 
# and modify messages and get the benefits of user communication.