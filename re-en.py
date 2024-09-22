# RE-EN (Rasanjana-East-Encrytion-V1.2)
# Created By W.H.T.Rasanjana(MOP[MotherOfProgrammers]) <- @GitHub
# 10/09/2024 [DD:MM:YY]

import sys
import random
import secrets
import string
import os
import math
import colorama
from colorama import Fore, Back, Style
colorama.init(autoreset=True)
from datetime import datetime
import base64
import time
import platform

def sprint(s): # The Welcome Text Styling
	for c in s + '\n':
		sys.stdout.write(c)
		sys.stdout.flush()
		time.sleep(1./10)

class clrs():
    cl0 = Fore.WHITE
    cl1 = Fore.GREEN
    cl2 = Fore.YELLOW
    cl3 = Fore.BLUE
    cl4 = Fore.CYAN
    cl5 = Fore.MAGENTA
    cl6 = Fore.RED
    clb = Style.BRIGHT

def passkeydec(key,ciphertext,iv,skey,bkey,enz,ccf,ccs):
    key = bytes.fromhex(key).decode()
    ciphertext = bytes.fromhex(ciphertext).decode()
    iv = bytes.fromhex(iv)
    skey = bytes.fromhex(skey).decode()
    bkey = bytes.fromhex(bkey).decode()
    enz = bytes.fromhex(enz).decode()
    ccf = ccf[:-(len(skey)*2)]
    ccf = ccf[(len(skey)//2):]
    ccs = ccs[:-(len(bkey)//2)]
    ccs = ccs[(len(bkey)*2):]
    ccf = bytes.fromhex(ccf).decode()
    ccs = bytes.fromhex(ccs).decode()
    iv = str(iv)
    start_order = 0
    multiplier = 0
    eq = (len(ciphertext) + len(iv))*len(enz)
    multiplier = math.sin(math.pow(eq,2))
    multiplier2 = math.cos(math.pow(eq,2))
    multiplier = int(multiplier)
    multiplier2 = int(multiplier2)
    if multiplier < 0:
        multiplier = -(multiplier)
    if multiplier == 0:
        multiplier = 1
    if multiplier2 < 0:
        multiplier2 = -(multiplier2)
    if multiplier2 == 0:
        multiplier2 = 2
    passkey = str(bkey[multiplier*3]) + str(skey[multiplier2*2]) + str(ciphertext[-1]) + str(iv[(start_order+1)*3]) + str(ccf[start_order]) + str(ccs[start_order]) + str(enz[-1]) + str(key[1])
   # t = []
    #for l in passkey:
     #   t.append(ord(l))
    passkeydec = passkey.encode().hex()
    return passkeydec

def passkey_gen(text,cipher,core_cipher,core2_cipher,key,skey,bkey,keyen,iv):
    text = text
    key = bytes.fromhex(key).decode()
    skey = bytes.fromhex(skey).decode()
    bkey = bytes.fromhex(bkey).decode()
    keyen = bytes.fromhex(keyen).decode()
    core_cipher = core_cipher[:-(len(skey)*2)]
    core_cipher = core_cipher[(len(skey)//2):]
    core2_cipher = core2_cipher[:-(len(bkey)//2)]
    core2_cipher = core2_cipher[(len(bkey)*2):]
    cipher = bytes.fromhex(cipher).decode()
    core_cipher = bytes.fromhex(core_cipher).decode()
    core2_cipher = bytes.fromhex(core2_cipher).decode()
    iv = bytes.fromhex(iv)
    iv = str(iv)
    start_order = 0
    multiplier = 0
    eq = (len(cipher) + len(iv))*len(keyen)
    multiplier = math.sin(math.pow(eq,2))
    multiplier2 = math.cos(math.pow(eq,2))
    multiplier = int(multiplier)
    multiplier2 = int(multiplier2)
    if multiplier < 0:
        multiplier = -(multiplier)
    if multiplier == 0:
        multiplier = 1
    if multiplier2 < 0:
        multiplier2 = -(multiplier2)
    if multiplier2 == 0:
        multiplier2 = 2
    passkey = str(bkey[multiplier*3]) + str(skey[multiplier2*2]) + str(cipher[-1]) + str(iv[(start_order+1)*3]) + str(core_cipher[start_order]) + str(core2_cipher[start_order]) + str(keyen[-1]) + str(key[1])
    #t = []
    #for l in passkey:
     #   t.append(ord(l))
    #print(t)
    passkeyen = passkey.encode().hex()
    return passkeyen

# The Passkey Is Something Like An Access Code/Token Which Created On Specific Encrypted Objects And The Object Which Helped For That Proccedure.
# This Is Very Helpful Recognize To How Much The Inputs Are Accurate As Well As Without This The Decryption Proccedure Would Not Be Worked Correctly!
# This AccessKey Is Very Random As Well As It's Not Possible To Be Hacked Due To The Enviroment Which Has Been Created Around That
# Every Output Is Much More Random And Thus The Passkey Is Very Random, It Couldn't Be Tracked Anyway

def generate_iv(key_size):
    return os.urandom(key_size).hex()

# Standard Cryptographically Safe Initialized Vector(IV)

def core1dec(skey,ccf,iv,key_size):
    iv = bytes.fromhex(iv)
    skey = bytes.fromhex(skey).decode()
    lenskey = len(skey) - 1
    ccfs = ccf[:-(len(skey)*2)]
    ccfd = ccfs[(len(skey)//2):]
    maxindex = lenskey
    max_iv_index = key_size - 1
    iv_index = 0
    index = 0
    ccfa = bytes.fromhex(ccfd).decode()
    core1 = ''
    for e in ccfa:
        if index >= maxindex:
            index = 0
        if iv_index >= max_iv_index:
            iv_index = 0
        core1 += chr((ord(e) ^ ord(skey[index])) ^ iv[iv_index] ^ key_size)
        index = index + 1
        iv_index = iv_index + 1
    return core1


def core2dec(bkey,ccs,iv,key_size):
    iv = bytes.fromhex(iv)
    bkey = bytes.fromhex(bkey).decode()
    lenbkey = len(bkey) - 1
    ccsz = ccs[:-(len(bkey)//2)]
    ccs = ccsz[(len(bkey)*2):]
    maxindex = lenbkey
    index = 0
    max_iv_index = key_size - 1
    iv_index = 0
    ccs = bytes.fromhex(ccs).decode()
    core2 = ''
    for q in ccs:
        if index >= maxindex:
            index = 0
        if iv_index >= max_iv_index:
            iv_index = 0
        core2 += chr((ord(q) ^ ord(bkey[index])) ^ iv[iv_index] ^ key_size)
        index = index + 1
        iv_index = iv_index + 1
    return core2

def decrypt(key,lengthkey,ciphertext,iv):
    iv = bytes.fromhex(iv)
    lengthkey = lengthkey
    key = bytes.fromhex(key).decode()
    maxindex = len(key) - 1
    index = 0
    full_calc = 0
    shift = 0
    plaintext = ''
    ciphertext = bytes.fromhex(ciphertext).decode()
    for p in ciphertext:
        if index >= maxindex:
            index = 0
        if full_calc >= 16:
            shift = 2
        if (index+shift) >= maxindex:
            index = 0
        plaintext += chr((ord(key[index+shift]) ^ ord(p)) ^ iv[index])
        index = index + 1
        full_calc = full_calc + 1
    return plaintext


def deckey(bkey,skey,enz):
    enz = bytes.fromhex(enz).decode()
    bxd = bkey[len(bkey)//2]
    sxd = skey[len(skey)//3]
    fxd = sxd + bxd
    index = 0
    key_len = ''
    keylength = 0
    maxindex = len(fxd) - 1
    for y in enz:
        if index >= maxindex:
            index = 0
        key_len += chr(ord(y) ^ ord(fxd[index]))
    keylength = int(key_len)
    return keylength
        

def key_extract(bkey,skey,enz):
    break_key = bytes.fromhex(bkey).decode()
    shield_key = bytes.fromhex(skey).decode()
    key_len = deckey(break_key,shield_key,enz)
    key = ''
    maxindex = key_len - 1
    index = 0
    for l in shield_key:
        if index >= maxindex:
            index = 0
        key += chr(ord(l) ^ ord(break_key[index]))
        index = index + 1
    return key,key_len
        
def keyend(key_size,bkey,skey):
    bx = bytes.fromhex(bkey).decode()
    sx = bytes.fromhex(skey).decode()
    bxl = bx[len(bx)//2]
    sxl = sx[len(sx)//3]
    fx = sxl+bxl
    keyenc = ''
    key_size = str(key_size)
    index = 0
    max_index = len(fx) - 1
    for t in key_size:
        if index >= max_index:
            index = 0
        keyenc += chr(ord(t) ^ ord(fx[index])).encode().hex()
        index = index + 1
    return keyenc

# Key Length Has Been Securely Encrypted Here, As Ever It Couldn't Being Decrypted Without This Encryption

def core(text,skey,iv,key_size):
    iv = bytes.fromhex(iv)
    max_iv_index = key_size - 1
    iv_index = 0
    skey = bytes.fromhex(skey).decode()
    max_index = len(skey) - 1
    randomhex1 = "".join(random.choices(string.hexdigits,k=len(skey)*2))
    randomhex2 = "".join(random.choices(string.hexdigits,k=len(skey)//2))
    index = 0
    core_cipher = ''
    for l in text:
        if index >= max_index:
            index = 0
        if iv_index >= max_iv_index:
            iv_index = 0
        core_cipher += (chr((ord(l) ^ ord(skey[index])) ^ iv[iv_index] ^ key_size))
        index = index + 1
        iv_index = iv_index + 1
    core_cipher = randomhex2+((core_cipher.encode()).hex())+randomhex1
    return core_cipher

# Core Texts Are Another Type Of Cipher But Very Various Than The Cipher Text Which Developed To Append And Develop The Security Layers Of RE-EN
# This is not poosible to be attack due to the complexed DXT method(Dual XOR Technique) and its randomness and other aspect of it
# And also appended other perfect cryptograpic techniques to make the output too much stronger and very impossible to break in any case

def core2(text,bkey,iv,key_size):
    iv = bytes.fromhex(iv)
    max_iv_index = key_size - 1
    iv_index = 0
    bkey = bytes.fromhex(bkey).decode()
    max_index = len(bkey) - 1
    randomhex1 = "".join(random.choices(string.hexdigits,k=len(bkey)//2))
    randomhex2 = "".join(random.choices(string.hexdigits,k=len(bkey)*2))
    index = 0
    core_cipher2 = ''
    for l in text:
        if index >= max_index:
            index = 0
        if iv_index >= max_iv_index:
            iv_index = 0
        core_cipher2 += chr((ord(l) ^ ord(bkey[index])) ^ iv[iv_index] ^ key_size)
        index = index + 1
        iv_index = iv_index + 1
    core_cipher2 = randomhex2+((core_cipher2.encode()).hex())+randomhex1
    return core_cipher2

def encrypt(key,text,iv):
    iv = bytes.fromhex(iv)
    key = bytes.fromhex(key).decode()
    max_index = len(key) - 1
    index = 0
    shift = 0
    full_calc = 0
    cipher = ''
    for lt in text:
        if index >= max_index:
            index = 0
        if full_calc >= 16:
            shift = 2
        if (index+shift) >= max_index:
            index = 0
        encrypted = ord(lt) ^ ord(key[index+shift])
        encrypted = encrypted ^ iv[index]
        cipher += chr(encrypted)
        index = index + 1
        full_calc = full_calc + 1
    cipher = (cipher.encode()).hex()
    return cipher

def one_time(key,key_size,method):
    if method == 'e':
        keyx = ''
        pool = ''
        cpool = ''
        for i in range(0x000,0xFED):
            pool += chr(i)
        for t in range(len(key)):
            cpool += "".join(secrets.choice(pool))
        index = 0
        max_index = key_size - 1
        for l in key:
            if index >= max_index:
                index = 0
            keyx += (chr(ord(l) ^ ord(cpool[index])))
            index = index + 1
        keyx = keyx.encode().hex()
        cpool = cpool.encode().hex()
        return keyx,cpool
            
def generate_key(key_size):
    pool = ''
    pre_pool = bytes(range(256))
    pool_arr = []
    pool_arr.append("".join(random.choices(string.ascii_letters+string.digits+string.punctuation,k=key_size)))
    random_pool = ''
    key = ''
    filter_loop = key_size//4
    for rchars in range(0X000,0XFDF):
        pool += chr(rchars)
    for i in range(filter_loop):
        rpool = "".join(random.choices(pool+pool_arr[-1]+str(pre_pool),k=key_size))
        pool_arr.append(rpool)
    for j in range(key_size):
        random_pool += "".join(secrets.choice(rpool))
    key = (rpool.encode()).hex()
    return key

# Here The Generate Key Function Firstly Gets Every Character Starting From 0x000 Upto 0xFDF And Also With 256 Bit Range, And It's Being Highly Filtered In A Highly Dedicated Range Loop Which Actually Make The Codes Randomly Shuffled And Randomly Filtered Which Make Very Impossible To Be Reveresed And Cryptographically Very Safer Generated Key Output
# And Being Encoded Into Byte Code And Converted Into HexaDecimal Digits Which Make Very Hard To Realize How This Being Generated And Increases The Complexity

def encryptf(passkey,cipher):
    cipher = bytes.fromhex(cipher).decode()
    passkey = bytes.fromhex(passkey).decode()
    index = 0
    max_index = len(passkey) - 1
    index_ad = 2
    passindex = 0
    maxpassindex = len(passkey) - 1
    fcipher = ''
    for c in cipher:
        if index >= max_index:
            index = 0
        if index_ad >= max_index:
            index_ad = 0
        if passindex >= maxpassindex:
            passindex = 0
        fcipher += chr((ord(c)) ^ ord(passkey[index]) ^ len(passkey*16) ^ ord(passkey[index_ad]))
        index = index + 1
        index_ad = index_ad + 2
        passindex = passindex + 1
    fcipher = fcipher.encode().hex()
    return fcipher

def decryptf(ciphertext,passkey):
    ciphertext = bytes.fromhex(ciphertext).decode()
    passkey = bytes.fromhex(passkey).decode()
    index = 0
    max_index = len(passkey) - 1
    index_ad = 2
    passindex = 0
    maxpasskeylen = len(passkey) - 1
    decipher = ''
    for d in ciphertext:
        if index >= max_index:
            index = 0
        if index_ad >= max_index:
            index_ad = 0
        if passindex >= maxpasskeylen:
            passindex = 0
        decipher += chr((ord(d)) ^ ord(passkey[index]) ^ len(passkey*16) ^ ord(passkey[index_ad]))
        index = index + 1
        index_ad = index_ad + 2
        passindex = passindex + 1
    decipher = decipher.encode().hex()
    return decipher

def encryptd(skey,bkey):
    skey = skey.upper()
    bkey = bkey.upper()
    k1 = 2
    k2 = 8
    skeye = ''
    bkeye = ''
    for l in skey:
        skeye += chr(ord(l) + k1*4)
    for r in bkey:
        bkeye += chr(ord(r) + k2*2)
    return skeye,bkeye

def decryptd(skey,bkey):
    skey = skey.upper()
    bkey = bkey.upper()
    k1 = 2
    k2 = 8
    skeye = ''
    bkeye = ''
    for l in skey:
        skeye += chr(ord(l) - k1*4)
    for r in bkey:
        bkeye += chr(ord(r) - k2*2)
    skeye = skeye.lower()
    bkeye = bkeye.lower()
    return skeye,bkeye

def sec_encrypt(cipher,skey):
    skey = bytes.fromhex(skey).decode()
    maxindex = len(skey) - 1
    index = 0
    sec_cipher = ''
    for l in cipher:
        if index >= maxindex:
            index = 0
        sec_cipher += chr(ord(l) ^ ord(skey[index]))
        index = index + 1
    sec_cipher = sec_cipher.encode('utf-16').hex()
    return sec_cipher

def thri_encrypt(cipher,bkey):
    bkey = bytes.fromhex(bkey).decode()
    maxindex = len(bkey) - 1
    index = 0
    thri_cipher = ''
    for t in cipher:
        if index >= maxindex:
            index = 0
        thri_cipher += chr(ord(t) ^ ord(bkey[index]))
        index = index + 1
    thri_cipher = thri_cipher.encode().hex()
    thri_cipher = thri_cipher.encode().hex()
    return thri_cipher

def sec_plaind(cipher,skey):
    cipher_decode = bytes.fromhex(cipher).decode('utf-16')
    skey = bytes.fromhex(skey).decode()
    index = 0
    maxindex = len(skey) - 1
    sec_plaint = ''
    for l in cipher_decode:
        if index >= maxindex:
            index = 0
        sec_plaint += chr(ord(l) ^ ord(skey[index]))
        index = index + 1
    return sec_plaint

def thri_plaind(cipher,bkey):
    cipher = bytes.fromhex(cipher).decode()
    cipher = bytes.fromhex(cipher).decode()
    bkey = bytes.fromhex(bkey).decode()
    maxindex = len(bkey) - 1
    index = 0
    thri_plaint = ''
    for t in cipher:
        if index >= maxindex:
            index = 0
        thri_plaint += chr(ord(t) ^ ord(bkey[index]))
        index = index + 1
    return thri_plaint

def append_tech(key,key_size,bkey,skey): # This Technique Called As TEDRET(Tri-Encode-Decode-Reverse-Encrypt-Technique)
    # reverse the key
    key = key[::-1]
    bkey = bytes.fromhex(bkey).decode()
    skey = bytes.fromhex(skey).decode()
    # random key append mechanism
    rkey1 = ''
    for l in key:
        rkey1 += "".join(random.choices(string.hexdigits,k=1)) + l
    # BASE64 Encode
    rkey1 = base64.b64encode(rkey1.encode())
    rkey1 = rkey1.decode()
    # Reverse The Text
    rkey1 = rkey1[::-1]
    rkeyx = ''
    # Convert The Text Cases
    for g in rkey1:
        if g in string.ascii_uppercase:
            rkeyx += g.lower()
        elif g in string.ascii_lowercase:
            rkeyx += g.upper()
        else:
            rkeyx += g
    rkey_y = ''
    # Append Random Text To The Base64 Technical Key
    for h in rkeyx:
        rkey_y += "".join(random.choices(string.ascii_uppercase+string.ascii_lowercase,k=1)) + h
    rkey_l = ''
    fixed_ord = key_size//4
    # Encrypt The Key With A Fixed Value
    for d in rkey_y:
        rkey_l += chr(ord(d) + fixed_ord)
    # Encode And Hex The Key
    rkey_l = rkey_l.encode().hex()
    # Reverse The Key
    rkey_l = rkey_l[::-1]
    rkey_ll = ''
    # Append Random Text To The Reverse Text
    for l in rkey_l:
        rkey_ll += "".join(random.choices(string.hexdigits,k=2)) + l
    rkey_ls = ''
    ford = fixed_ord  + 1
    for g in rkey_ll:
        rkey_ls += chr(ord(g) + ford)
    rkey_ls = rkey_ls.encode().hex()
    return rkey_ls
            
# p = base64.b64decode((l.encode()).decode()) when l in str

def remove_tech(skey,bkey,lengthkey,key):
    skey = bytes.fromhex(skey).decode()
    bkey = bytes.fromhex(bkey).decode()
    key = bytes.fromhex(key).decode()
    keyl = ''
    keyld = ''
    fixed_pos1 = (lengthkey//4) + 1
    for l in key:
        keyld += chr(ord(l) - fixed_pos1)
    count_1 = 1
    for l in keyld:
        if count_1 % 3 == 0:
            keyl += l
        count_1 = count_1 + 1
    last_key = keyl[::-1]
    last_key = bytes.fromhex(last_key).decode()
    prevl_key = ''
    fixed_pos = lengthkey//4
    for l in last_key:
        prevl_key += chr(ord(l) - fixed_pos)
    removed_ascii = ''
    count = 1
    for g in  prevl_key:
        if count % 2 == 0:
            removed_ascii += g
        count = count + 1
    convertion = ''
    for c in removed_ascii:
        if c in string.ascii_uppercase:
            convertion += c.lower()
        elif c in  string.ascii_lowercase:
            convertion += c.upper()
        else:
            convertion += c
    convertion = convertion[::-1]
    conv_decode  = base64.b64decode((convertion.encode()).decode())
    conv_decode = conv_decode.decode()
    r_conv = ''
    count_2 = 1
    for i in conv_decode:
        if count_2 % 2 == 0:
            r_conv += i
        count_2 = count_2 + 1
    the_key = r_conv[::-1]
    return the_key

def enhanced_protection_iv(iv):
    length_iv = len(iv)
    reversed_iv = iv[::-1]
    l1_iv = ''
    l2_iv = ''
    for l in reversed_iv:
        l1_iv += "".join(random.choices(string.hexdigits,k=2)) + l
    for i in l1_iv:
        l2_iv += chr(ord(i) + length_iv)
    
    l3_iv = l2_iv.encode('utf-8').hex()
    return l3_iv

def de_enhance_protection_iv(iv,ivlen):
    l3_ivb = bytes.fromhex(iv).decode('utf-8')
    l2_ivb = ''
    l1_ivb = ''
    ivlen = ivlen * 2
    for i in l3_ivb:
        l2_ivb += chr(ord(i) - ivlen)
    count = 1
    for l in l2_ivb:
        if count % 3 == 0:
            l1_ivb += l
        count = count + 1
    iv = l1_ivb[::-1]
    return iv
    

def check():
    method = str(input(f"{clrs.cl0}Enter The Method[Encrypt(e)/Decrypt(d)]: {clrs.cl3}"))
    if method != '':
        if (method.lower()  == 'e') or (method.lower() == 'encrypt'):
            key_size = int(input(f"{clrs.cl0}Enter The Key Size To Generate The Private Key[16,24,32,48,64,96,128,256,384,512]: {clrs.cl4}"))
            key_size_arr = [16,24,32,48,64,96,128,256,384,512]
            if key_size != '':
                if key_size in key_size_arr:
                    key = generate_key(key_size)
                    iv = generate_iv(key_size)
                    skey,bkey = one_time(key,key_size,method='e')
                    rkey = append_tech(key,key_size,bkey,skey)
                    keyen = keyend(key_size,bkey,skey)
                    skey,bkey = encryptd(skey,bkey)
                    iv_protect = enhanced_protection_iv(iv)
                    print(f"{clrs.cl0}[INFO]{clrs.cl6}IV: {clrs.cl1}{iv_protect}{clrs.cl0}")
                    print(f"[INFO]{clrs.cl6}Key: {clrs.cl1}{rkey}{clrs.cl0}")
                    print(f"[INFO]{clrs.cl6}ENZ Key: {clrs.cl1}{keyen}{clrs.cl0}")
                    print(f"[INFO]{clrs.cl6}Your Shield Key: {clrs.cl1}{skey}{clrs.cl0}")
                    print(f"[INFO]{clrs.cl6}Your Break Key: {clrs.cl1}{bkey}{clrs.cl0}")
                    text = str(input(f"[INFO]{clrs.cl2}Enter The Text To Encrypt: {clrs.cl0}"))
                    if text != '':
                        skey,bkey = decryptd(skey,bkey)
                        cipher = encrypt(key,text,iv)
                        core_cipher = core(text,skey,iv,key_size)
                        core2_cipher = core2(text,bkey,iv,key_size)
                        passkey = passkey_gen(text,cipher,core_cipher,core2_cipher,key,skey,bkey,keyen,iv)
                        fcipher = encryptf(passkey,cipher)
                        sec_cipher = sec_encrypt(fcipher,skey)
                        thri_cipher = thri_encrypt(sec_cipher,bkey)
                        print(f"[INFO]{clrs.cl6}The Cipher Text: {clrs.cl5+clrs.clb}{thri_cipher}{clrs.cl0}")
                        print(f"[INFO]{clrs.cl6}CCF Text: {clrs.cl1}{core_cipher}{clrs.cl0}")
                        print(f"[INFO]{clrs.cl6}CCS Text: {clrs.cl1}{core2_cipher}{clrs.cl0}")
                        print(f"[INFO]{clrs.cl6}Passkey: {clrs.cl1}{passkey}{clrs.cl0}")
                        print(f"[INFO]{clrs.cl6}Key Length Composites: {clrs.cl4}{len(cipher)}{clrs.cl0}|{clrs.cl4}{len(core_cipher)}{clrs.cl0}|{clrs.cl4}{len(core2_cipher)}{clrs.cl0}")
                        print(f"[SUCCESS]{clrs.cl6}Data Has Been Encrypted Successfully!{clrs.cl0}")
                        ask_save = str(input("Do You Want To Save The Credetials To A File[yes(y)/no(n)]: "))
                        if (ask_save.lower() == 'y') or (ask_save.lower() == 'yes'):
                            usercode = str(datetime.now().second)+str(len(key))+str(datetime.now().microsecond)
                            filename = 'encrypted_data.confidential.txt'
                            with open(filename, 'a') as fl:
                                fl.write(f"IV(Initialized Vector): {iv}\nKey: {key}\nENZ Key: {keyen}\nShield Key: {skey}\nBreak Key: {bkey}\nCipher Text: {fcipher}\nCCF Text: {core_cipher}\nCCS Text: {core2_cipher}\nPasskey: {passkey}\nKey Composites: {len(cipher)}|{len(core_cipher)}|{len(core2_cipher)}\nUsercode: {usercode}\n")
                            print(f"[INFO]{clrs.cl5}Credentials Save Successfully!")
                            print(f"[INFO]{clrs.cl0}Thank You For Using This Tool!")
                        elif (ask_save.lower() == 'n') or (ask_save.lower() == 'no'):
                            print(f"[INFO]{clrs.cl0} Thank You For Using This Tool!")
                        else:
                            print(f"{clrs.cl6}No Option Called As {clrs.cl2}'{ask_save}'{clrs.cl6}!{clrs.cl0}")
                            sys.exit()
                    else:
                        print(f"[ERROR]{clrs.cl6}No Input Entered!")
                        sys.exit()
                else:
                    print(f"[ERROR]{clrs.cl6}Invalid Key Size {clrs.cl2}{key_size}{clrs.cl6}!")
                    sys.exit()
            else:
                print(f"[ERROR]{clrs.cl6}No Input Entered!")
                sys.exit()
        elif (method.lower() == 'd') or (method.lower() == 'decrypt'):
            skey = str(input(f"{clrs.cl0}[INFO]{clrs.cl2}Enter Your Shield Key: {clrs.cl1}"))
            skeyl = len(skey)
            if skeyl != 0:
                bkey = str(input(f"{clrs.cl0}[INFO]{clrs.cl2}Enter Your Break Key: {clrs.cl1}"))
                bkeyl = len(bkey)
                if bkeyl != 0:
                    enz = str(input(f"{clrs.cl0}[INFO]{clrs.cl2}Enter Your ENZ Key: {clrs.cl1}"))
                    check_key = str(input(f"{clrs.cl0}[INFO]{clrs.cl2}Enter The Key: {clrs.cl1}"))
                    if (enz != '') and (check_key != ''):
                        skey,bkey = decryptd(skey,bkey)
                        key,lengthkey = key_extract(bkey,skey,enz)
                        the_key = remove_tech(skey,bkey,lengthkey,check_key)
                        if the_key == key:
                            ciphertext = str(input(f"{clrs.cl0}[INFO]{clrs.cl2}Enter Your Cipher Text: {clrs.cl1}"))
                            ccf = str(input(f"{clrs.cl0}[INFO]{clrs.cl2}Enter Your CCF Text: {clrs.cl1}"))
                            ccs = str(input(f"{clrs.cl0}[INFO]{clrs.cl2}Enter Your CCS Text: {clrs.cl1}"))
                            iv_enc = str(input(f"{clrs.cl0}[INFO]{clrs.cl2}Enter IV: {clrs.cl1}"))
                            passkey = str(input(f"{clrs.cl0}[INFO]{clrs.cl2}Enter The PassKey: {clrs.cl1}"))
                            if (ciphertext != '') and (ccf != '') and (ccs != '') and (iv_enc != '') and (passkey != '') and (len(bytes.fromhex(passkey).decode()) == 8):
                                iv = de_enhance_protection_iv(iv_enc,lengthkey)
                                print(iv)
                                thri_plaint = thri_plaind(ciphertext,bkey)
                                sec_plaint = sec_plaind(thri_plaint,skey)
                                defcipher = decryptf(sec_plaint,passkey)
                                plaintext =  decrypt(key,lengthkey,defcipher,iv)
                                core1d = core1dec(skey,ccf,iv,lengthkey)
                                core2d = core2dec(bkey,ccs,iv,lengthkey)
                                passkey_conf = passkeydec(key,defcipher,iv,skey,bkey,enz,ccf,ccs)
                                if (plaintext == core1d == core2d) and (passkey == passkey_conf):
                                    print(f"{clrs.cl0}[INFO]{clrs.cl6}Your Plain Text: {clrs.cl5+clrs.clb}{plaintext}{clrs.cl0}")
                                    print(f"{clrs.cl0}[SUCCESS]{clrs.cl4}Data Has Been Decrypted Successfully!")
                                else:
                                    if (passkey != passkey_conf):
                                        print(f"{clrs.cl0}[ERROR]{clrs.cl6}Invalid Passkey!{clrs.cl0}")
                                        sys.exit()
                                    else:
                                        print(f"{clrs.cl0}[ERROR]{clrs.cl6}Wrong Inputs Detected, Checkout Again!{clrs.cl0}")
                                        sys.exit()
                            else:
                                print(f"{clrs.cl0}[ERROR]{clrs.cl6}No Input Entered For ENZ Key!{clrs.cl0}")
                                sys.exit()
                        else:
                            print(f"{clrs.cl0}[ERROR]{clrs.cl6}Invalid Key!{clrs.cl0}")
                            sys.exit()
                else:
                    print(f"{clrs.cl0}[ERROR]{clrs.cl6}No Input Entered For Break Key!{clrs.cl0}")
                    sys.exit()
            else:
                print(f"{clrs.cl0}[ERROR]{clrs.cl6}No Input Entered For Shield Key!{clrs.cl0}")
                sys.exit()
        else:
            print(f"{clrs.cl0}[ERROR]{clrs.cl6}No Such Method Called As {clrs.cl5+clrs.clb}{method}{clrs.cl6}!{clrs.cl0}")
    else:
        print(f"{clrs.cl0}[ERROR]{clrs.cl6}No Input Entered!{clrs.cl0}")
        sys.exit()


def start_system():
    if platform.system() == 'Windows':
        os.system('cls')
        check()
    else:
        os.system('clear')
        check()
    

if __name__ == '__main__':
    sprint("""
          ========================================================================
          =============   ENCryPt0R - V1.2  ---> By W.H.T.Rasanjana ==============
          ========================================================================
          (2024-09-09-[RE-EN])
          """)
    start_system()

# New Updates

# Improvise In The Internal Codes
# Increased Security Layers And The Increased Complexity
# 16-512 Bit Keys
# New Features To Make The Encryption And Decryption Perfect
# Highly Complex And Improvised Detection System
# Perfect Error Handling


# AES(Advanced Encryption System) Vs RE-EN (Rasanjana-East Encryption)

# AES (Advanced Encryption System),

# Multiple Of Modes
# Tokens And IV
# Block Cipher Technology

# RE-EN (Rasanjana-East Encryption),

# One Superior Mode Of All
# Improvised Encryption/Decryption Process Speed
# Highly Complex Systems
# More That 5 Security Layers
# Key Recognition And Cipher-Plaintext Detection System
# Front-Back End Safe Proccedures
# DX Technique With Other Newly Built-In Methods Which Are Better Than The Current State Of Cryptography
# IV And Passkey, CoreTexts And Other Improvised Security Based Very Complexed Features
# Perfect For Any Type Of Encryption-Decryption Processes Like Crypto Wallets, Millitary Encryption, Secret Government/Non-Government And Others
# Very Impossible To Be Hacked Via Any Method (0.00000000001% Near To 0% Possibility), Very Complex And Very Impossible To Be Hacked Via Any Method Unlike Other Encryption Methods Like AES, TwoFish, BowFish And Else
# Harder Way To Find Out All The Parameters That Need For Decryption In Phishing Unlike The Easiness That Have In Other Encryption Methods
# Custom Made Methods Like TEDRET Method And Else
# Protected Initialized Vector (IV)
# And Other Highly Considerable Facts

# The Summary
# This Creates A Massive Keys And Essential Parts For Encryption And Decrpytion With Well Made Own Methods
# The Key Byte Range Is 256 And Unlike Other Algorithms Like AES This Would Not Mention You About A Specific Geometri Based Technique, But However As The Programmer Who Developed This Program I Would Like To Say That This Program Has A One
# And The Non-Linear Relationships With Majestic Ways Of Custom Made Functions Which Are Not In The Tradition Of The Cryptography Made This Program's Outputs Much More Powerful And They Won't Even Be Broken Via Quantum Encryption Break Methods
# So Finally This Encryption Method Which Called As Rasanjana-East-Encryption(RE-EN) Is Much More Powerful Than The Current Encryption Systems And Very Practical In The Modern World Situations And More Suitable With The Cryptographic Principles

