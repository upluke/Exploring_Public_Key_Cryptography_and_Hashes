from hashlib import sha256
from itertools import count 
from time import perf_counter
import matplotlib.pyplot as plt
import numpy as np
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

def same_digest(bits: int = 32):
    check={} 
    bit_mask = 2**bits -1 # f"{2**5-1:b}"
    num_of_input_count =0
    for i in range(2**32):
        num_of_input_count+=1
        byte_obj= i.to_bytes(4, 'big') 
        curr_hash =  sha256(byte_obj).digest()  
        truncated_hash=  int.from_bytes(curr_hash, 'big')&bit_mask
        if truncated_hash in check:
            # print("The string", byte_obj, "and the string", check[truncated_hash], "has the same digest.")
            print("num of input count:", num_of_input_count)
            
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
    
    # For multiples of 2 bits (i.e. for digests sized 8, 10, 12, ..., 48, 50 bits), 
    # measure both the number of inputs and the total time for a 
    # collision to be found. Create two graphs: one which plots digest size 
    # (along the x-axis) to collision time (y-axis), and one which plots digest size
    # to number of inputs. Include these graphs in your report.
    
    
    # graph example: 
    # t = np.arange(0.0, 2.0, 0.01)
    # s = 1 + np.sin(2 * np.pi * t)

    # fig, ax = plt.subplots()
    # ax.plot(t, s)

    # ax.set(xlabel='time (s)', ylabel='voltage (mV)',
    #     title='About as simple as it gets, folks')
    # ax.grid()

    # fig.savefig("test.png")
    # plt.show()
   
    
    for bits in range(2,52,2):
        # start_time =perf_counter()
        print("digest size: ",bits)
        same_digest(bits)
        # end_time =perf_counter() 
        # print("digest size:", bits, " collision time: ", end_time - start_time)
        print()
    
    # when truncate to 4 bytes:  The string b'\x00\x00\xb2T' and the string b'\x00\x00\xa06' has the same digest.
    
    