from dhp import dhp

from Crypto.Cipher import AES
from hashlib import sha256

import random
from Crypto.Util.Padding import pad, unpad

class Person:
    def __init__(self, p: int, g: int):
        self.p = p
        self.g = g
        self.private_key= random.randint(2,p-1) # a/b
        self.public_key =pow(self.g, self.private_key, self.p)  
        self.s = 0
        self.k = b'' # default bytes obj
    
    def calculate_shared_num_and_key(self, other_person_public_key: int):
        self.s = pow(other_person_public_key, self.private_key, self.p)
        self.k = sha256(self.s.to_bytes(128, 'big')).digest()[:16]
    
    # encrypt a msg and return the encrypted msg
    def encrypt_msg(self, m: str):
        # turn it into bytes and pad it
        m_bytes = pad(m.encode(), 16)
        # make encryptor objects
        encryptor =  AES.new(self.k, AES.MODE_CBC, iv=self.k) 
        return encryptor.encrypt(m_bytes)
    
    def decrypt_msg(self, cipher_text:bytes) -> str:
        decryptor = AES.new(self.k, AES.MODE_CBC, iv = self.k)
        m_received = unpad(decryptor.decrypt(cipher_text), 16)
        
        return m_received.decode() # convert byte to str
        
def dhp(p: int, g: int, m_alice: str, m_bob: str):
    alice = Person(p, g)
    bob = Person(p, g)
    
    alice.calculate_shared_num_and_key(bob.public_key)
    bob.calculate_shared_num_and_key(alice.public_key)
    
    ctext_alice =  alice.encrypt_msg(m_alice)
    ctext_bob =  bob.encrypt_msg(m_bob)
    m_alice_received =  alice.decrypt_msg(ctext_bob)
    m_bob_received =  bob.decrypt_msg(ctext_alice)
    
    print(f"{m_alice_received = }")
    print(f"{m_bob_received = }")
    

    
# TODO: complete mitm 
def mitm(p: int , g: int, m_alice: str, m_bob: str):
    alice = Person(p, g)
    bob = Person(p, g)
    
    
    # Mallry tricks : A->p B->p
    alice.calculate_shared_num_and_key(p)
    bob.calculate_shared_num_and_key(p)
    
    ctext_alice =  alice.encrypt_msg(m_alice)
    ctext_bob =  bob.encrypt_msg(m_bob)
    
    # Mallry comutes k with s is 0 becuase both Aplice and Bob think s = p^a % p = 0 
    k = sha256((0).to_bytes(128, 'big')).digest()[:16]
    
    # Alice and Bob can still see their msgs without knowing Mallry's existance
    m_alice_received =  alice.decrypt_msg(ctext_bob)
    m_bob_received =  bob.decrypt_msg(ctext_alice)
    
    print(f"{m_alice_received = }")
    print(f"{m_bob_received = }")
    
    # Mallry decrypts the object 
    decryptor_mallry_for_alice= AES.new(k, AES.MODE_CBC, iv=k)
    decryptor_mallry_for_bob= AES.new(k, AES.MODE_CBC, iv=k) 
    
    m_mallry_for_alice= unpad(decryptor_mallry_for_alice.decrypt(ctext_alice), 16).decode()
    m_mallry_for_bob = unpad(decryptor_mallry_for_bob.decrypt(ctext_bob), 16).decode()
    
    print(f"{m_mallry_for_alice = }")
    print(f"{m_mallry_for_bob = }")
    