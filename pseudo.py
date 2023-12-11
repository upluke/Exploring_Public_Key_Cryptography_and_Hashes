from hashlib import sha256
from itertools import count 


# Start by writing a program that uses SHA256 to hash arbitrary 
# inputs and print the resulting digests to the screen in hexadecimal format.
# Next, hash two strings (of any length) whose Hamming Distance is exactly 
# 1 bit (i.e. differ in only 1 bit). Repeat this a few a times.
def print_sha256(s:bytes):
    
    print(sha256(s).hexdigest())

# Now, let’s try to find two strings that create the same digest (called a collision). 
# Because SHA256 is a secure cryptographic hash function (as far as we know), 
# its not feasible to use its full 256-bit output.  Instead, 
# you will limit its domain to between 8 and 50 bits
# 2. Maximize your chances of finding a collision by relying on the Birthday Problem: For any two messages m0, m1 where m0 ≠ m1, find H(m0) = H(m1). This requires a little more code (and memory usage), but will find a collision more quickly. Consider using a hashtable or dictionary, but be careful about efficiency as finding collision on 50-bit outputs is right at the edge of what’s feasible by an average computer.

# import matplotlib.pyplot as plt

def same_digest(bits: int = 32):
    check={}
    bit_mask = 2**bits -1 # f"{2**5-1:b}"
    for i in range(2**32):
        byte_obj= i.to_bytes(4, 'big') 
        curr_hash =  sha256(byte_obj).digest()  
        truncated_hash=  int.from_bytes(curr_hash, 'big')&bit_mask
        if truncated_hash in check:
            print("The string", byte_obj, "and the string", check[truncated_hash], "has the same digest.")
            break
         
        check[truncated_hash] = byte_obj
        
     


if __name__ == "__main__":
    # a= 01100001 b=01100010 c=01100011
    # c= 01100011 b=01100010 c=01100011
    s1= b"abc"
    s2= b"cbc"
    
    # print_sha256(s1)
    # print_sha256(s2)
    
    s3= b"abcdef"
    s4= b"abcdeg"
    # print_sha256(s3)
    # print_sha256(s4) 
    # What do you observe? How many of the bytes are different between the two digests?
    # all the bytes are different pretty much
    
    
    same_digest(50)
    # The string b'\x00\x00\xb2T' and the string b'\x00\x00\xa06' has the same digest.
    
    