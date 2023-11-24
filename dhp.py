from Crypto.Cipher import AES
from hashlib import sha256
import random
import urllib.parse

from Crypto.Util.Padding import pad, unpad

def dhp():
   g = 5
   p = 37
   alice_prviate_key = random.randint(2,p-1)  # ℤp 
   alice_public_key = pow(g, alice_prviate_key, p) # g^a % p
   
   
   bob_private_key = random.randint(2,p-1)
   bob_public_key = pow(g, bob_private_key, p)
   
   
   # A = alice_public_key
   # B = bob_public_key
   # s = shared secret = B^a mod p 
   
   s_alice = pow(bob_public_key, alice_prviate_key, p) 
   s_bob = pow(alice_public_key, bob_private_key, p)   
   # print( s_Alice, s_Bob)
   
   
   k_alice = sha256((s_alice).to_bytes(128, 'big')).digest() 
   k_alice = k_alice[:16]
   
   k_bob = sha256((s_bob).to_bytes(128, "big")).digest()
   k_bob = k_bob[:16]
   
   m_alice = "Hello wolrd!"
   m_alice = urllib.parse.quote_plus(m_alice)
   m_alice = pad(m_alice.encode(), 16)
   
   m_bob = "No thanks!"
   m_bob = urllib.parse.quote_plus(m_bob)
   m_bob = pad(m_bob.encode(), 16)
   
   c_alice = AES.new(k_alice, AES.MODE_CBC, iv=k_alice) # type: ignore
   c_bob = AES.new(k_bob, AES.MODE_CBC, iv=k_bob)
   
   
   ctext_bob = c_bob.encrypt(m_bob)
   m1 = unpad(c_alice.decrypt(ctext_bob), 16)
   m1 = urllib.parse.unquote_plus(m1.decode())
   print(m1)
   
  
dhp()
   

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



# g =
# A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
# D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
# 160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
# 909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
# D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
# 855E6EEB 22B3B2E5
