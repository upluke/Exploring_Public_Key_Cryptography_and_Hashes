from Crypto.Cipher import AES


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