#################################################################
#   Filename:   mdc2_with_aes.py                                #
#   Version:    Python 3.7.5                                    #
#   Author:     Tim Kohlstadt                                   #
#   Date:       2019-03-15                                      #
#################################################################

# Library "PyCryptodome" (https://pycryptodome.readthedocs.io/en/latest/index.html)

import binascii
from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256, SHA3_512
from hwcounter import Timer, count, count_end
import sys
import time

# Set CLOCK_CYCLES if the elapsed clock cycles should be printed or not
#CLOCK_CYCLES = True
CLOCK_CYCLES = False

# Set RUNTIME If the runtime is to be measured or not
#RUNTIME = True
RUNTIME = False

# Set RUNTIME_AES if the time of a single run of AES should be printed or not
#RUNTIME_AES = True
RUNTIME_AES = False

# Set RESULT if results should be printed or not
RESULT = True
#RESULT = False

if CLOCK_CYCLES == True:
  elapsed_clock_cycles = 0

if RUNTIME == True:
  time_xor_aes = 0

###############################################################################
### AES in ECB-mode (Electronic Code Book)                                  ###
###############################################################################

#######################
## function definition
##

def encrypt(key, data, aesni):
    if CLOCK_CYCLES == True:
        global elapsed_clock_cycles
        start = count()
    
    encryption_suite = AES.new(key, AES.MODE_ECB, use_aesni=aesni)
    cipher_text = encryption_suite.encrypt(data)
    
    if CLOCK_CYCLES == True:
        elapsed_clock_cycles += count_end() - start
        print(f'elapsed_clock_cycles: {elapsed_clock_cycles}')
    
    return cipher_text
    
def decrypt(key, cipher_text, aesni):
    if CLOCK_CYCLES == True:
        global elapsed_clock_cycles
        start = count()
    
    decryption_suite = AES.new(key, AES.MODE_ECB, use_aesni=aesni)
    plain_text = decryption_suite.decrypt(cipher_text)
    
    if CLOCK_CYCLES == True:
        elapsed_clock_cycles += count_end() - start
        print(f'elapsed_clock_cycles: {elapsed_clock_cycles}')
    
    return plain_text

#######################
## function calls
##

if RUNTIME_AES == True:
    # 16 characters (16 bytes / 128 bit)
    key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
    data = b'\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a'
    
    print("\nRuntime AES without AES-NI:")
    start_time = time.time()
    start_proc = time.process_time()
    
    cipher_text = encrypt(key, data, False)
    
    time_proc = (time.process_time() - start_proc) * 1000
    time_time = (time.time() - start_time) * 1000
    print("encrypt: %.5f ms (time() function) | %.5f ms (process_time() function)." % (time_time, time_proc))
    
    start_time = time.time()
    start_proc = time.process_time()
    
    plain_text = decrypt(key, cipher_text, False)
    
    time_proc = (time.process_time() - start_proc) * 1000
    time_time = (time.time() - start_time) * 1000
    print("decrypt: %.5f ms (time() function) | %.5f ms (process_time() function).\n" % (time_time, time_proc))
    
    
    print("Runtime AES with AES-NI:")
    start_time = time.time()
    start_proc = time.process_time()
    
    cipher_text = encrypt(key, data, True)
    
    time_proc = (time.process_time() - start_proc) * 1000
    time_time = (time.time() - start_time) * 1000
    print("encrypt: %.5f ms (time() function) | %.5f ms (process_time() function)." % (time_time, time_proc))
    
    start_time = time.time()
    start_proc = time.process_time()
    
    plain_text = decrypt(key, cipher_text, True)
    
    time_proc = (time.process_time() - start_proc) * 1000
    time_time = (time.time() - start_time) * 1000
    print("decrypt: %.5f ms (time() function) | %.5f ms (process_time() function).\n" % (time_time, time_proc))

# Both results tested with: http://aes.online-domain-tools.com


###############################################################################
### MDC-2 with AES                                                          ###
###############################################################################

#######################
## function definition
##

# Returns result of xor (16 bytes / 128 bit)
def logical_xor(str1, str2):
    # Convert the byte-arry str1 and str2 to binarys in a string
    str1 = bin(int(binascii.hexlify(str1), 16)).lstrip('0b')
    str2 = bin(int(binascii.hexlify(str2), 16)).lstrip('0b')
    # Compute the logical XOR of str1 and str2 as an integer
    result = int(str1,2) ^ int(str2,2)
    # Convert the integer result to binarys in a string and fill the length to 128
    result = bin(result)[2:].zfill(128)
    return result

def mdc2(message, iv_A, iv_B, blocksize, use_aesni):
    if RESULT == True:
        print("message length: %d byte." % (len(message)))
    
    # Add zeros if the message isn't a multiple of the blocksize
    if len(message) % blocksize != 0:
        for i in range(blocksize - (len(message) % blocksize)):
            message += b'0'
    
    # Split message in blocks by the blocksize
    array = [message[i:i+blocksize] for i in range(0, len(message), blocksize)]
    
    if RUNTIME == True:
        global time_xor_aes
        block_counter = 0
        time_xor_aes = 0
    
    # Algorithm from: https://en.wikipedia.org/wiki/MDC-2#Algorithm
    for block in array:
        if RUNTIME == True:
            start_time = time.time()
            start_proc = time.process_time()
        
        # Logical xor from the actual message block as bytes and the encryption as bytes
        v = logical_xor(block, encrypt(iv_A, block, use_aesni))
        w = logical_xor(block, encrypt(iv_B, block, use_aesni))
        
        if RUNTIME == True:
            ende_proc = time.process_time()
            time_xor_aes = time_xor_aes + ((time.time() - start_time))
        
        # Swap the second half of the two binary numbers
        len_v = int(len(v)/2)
        len_w = int(len(w)/2)
        vL, vR = v[:len_v], v[len_v:]
        wL, wR = w[:len_w], w[len_w:]
        a = vL + wR
        b = wL + vR
        # Convert the binarys 'a' and 'b' to the byte-arry 'iv_A' and 'iv_B' and
        # pad it on the left with zeros until the length is blocksize * 2
        iv_A = bytes.fromhex(format(int(a, 2), 'x').zfill(blocksize * 2))
        iv_B = bytes.fromhex(format(int(b, 2), 'x').zfill(blocksize * 2))
    
    if RUNTIME == True:
        print("Runtime AES_XOR: \t%.5f ms." % ((time_xor_aes) * 1000) )
    
    return (iv_A + iv_B).hex()

#######################
## function calls
##

# Blocksize n in byte
blocksize = 16

# Initialization vector A: \x52 hex is a 'R' as string
iv_A = b'\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52'
# Initialization vector B: \x25 hex is a '%' as string
iv_B = b'\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25\x25'


# 64 bytes / 512 Bits
#message = "e0a89090adfa0e1f1be62f5b3da546efc3dca7b767bbf3cc8684c7a38e56b4c5"

# 128 bytes / 1024 Bits
message = "e0a89090adfa0e1f1be62f5b3da546efc3dca7b767bbf3cc8684c7a38e56b4c5eda05836539b77415639e4028d425b7a0dda7ef21300da924470e279c549d371"

# Encode message to binary
message = message.encode('utf-8')

if CLOCK_CYCLES == True or RUNTIME == True or RESULT == True:
    print("\nMDC-2 with AES and without AES_NI:")

if RUNTIME == True:
    time_xor_aes = 0
    start_time = time.time()
    start_proc = time.process_time()

if CLOCK_CYCLES == True:
    elapsed_clock_cycles = 0
    start = count()

result = mdc2(message, iv_A, iv_B, blocksize, use_aesni=False)

if CLOCK_CYCLES == True:
    elapsed_clock_cycles = count_end() - start
    print("Clock-cycles for MDC-2 with AES and without AES_NI:")
    print(elapsed_clock_cycles)

if RUNTIME == True:
    ende_proc = time.process_time()
    time1 = (time.time() - start_time) * 1000
    print('Total time: \t\t{:5.3f}s'.format(time1))
    print('System time: \t\t{:5.3f}s'.format((ende_proc-start_proc)*1000))
    print("Runtime: \t\t%.5f ms (time() function) | %.5f ms (process_time() function)." % (time1, (ende_proc-start_proc)*1000))
    print("Runtime without AES: \t%.5f ms." % ((ende_proc-start_proc-time_xor_aes)*1000))

if RESULT == True:
    print("Result:")
    print(result)

if CLOCK_CYCLES == True or RUNTIME == True or RESULT == True:
    print("\n\nMDC-2 with AES and with AES_NI:")

if RUNTIME == True:
    time_xor_aes = 0
    start_time = time.time()
    start_proc = time.process_time()

if CLOCK_CYCLES == True:
    elapsed_clock_cycles = 0
    start = count()

result = mdc2(message, iv_A, iv_B, blocksize, use_aesni=True)

if CLOCK_CYCLES == True:
    elapsed_clock_cycles = count_end() - start
    print("Clock-cycles for MDC-2 with AES and with AES_NI:")
    print(elapsed_clock_cycles)

if RUNTIME == True:
    ende_proc = time.process_time()
    time2 = (time.time() - start_time) * 1000
    print('Total time: \t\t{:5.3f}s'.format(time2))
    print('System time: \t\t{:5.3f}s'.format((ende_proc-start_proc)*1000))
    print("Runtime: \t\t%.5f ms | %.5f ms." % (time2, (ende_proc-start_proc)*1000))
    print("Runtime without AES: \t%.5f ms.\n" % ((ende_proc-start_proc-time_xor_aes)*1000))

if RESULT == True:
    print("Result:")
    print(result)

if RUNTIME == True:
    time_absolut = time1 - time2
    print("Difference between MDC-2 with AES and with or without AES_NI:")
    if time_absolut > 0:
        print("MDC-2 with AES and with AES_NI is %.5f ms faster then without AES_NI." % (time_absolut))
    else:
        print("MDC-2 with AES and without AES_NI is %.5f ms faster then without AES_NI." % (time_absolut * (-1)))

###############################################################################
### SHA3 (256 and 512 bit)                                                  ###
###############################################################################

if CLOCK_CYCLES == True or RUNTIME == True or RESULT == True:
    print("\n\nSHA3_256:")

if RESULT == True:
    print("message length: %d byte." % (len(message)))

if CLOCK_CYCLES == True:
    elapsed_clock_cycles = 0
    start = count()

if RUNTIME == True:
    start_time = time.time()

h_obj = SHA3_256.new().update(message)
result = h_obj.hexdigest()

if CLOCK_CYCLES == True:
    elapsed_clock_cycles = count_end() - start
    print(elapsed_clock_cycles)

if RUNTIME == True:
    time3 = (time.time() - start_time) * 1000
    print(("Runtime: %.5f ms.\n" % (time3)))

if RESULT == True:
    print("Result:")
    print(result)

exit(0)
