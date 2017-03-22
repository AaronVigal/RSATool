#!/usr/bin/python
# -*- coding: utf-8 -*-
import argparse, os, requests, re, datetime, binascii, random
from fractions import gcd
from Crypto.PublicKey import RSA

# ---------- Add Arguments ---------- #
parser = argparse.ArgumentParser()
parser.add_argument("-x", "--hex", help="Given ciphertext 'c'", action="store_true")
parser.add_argument("-c", "--cipher_text", help="Given ciphertext 'c'", metavar='')
parser.add_argument("-n", "--modulus_n", help="Modulus n or (q * p)", metavar='')
parser.add_argument("-p", "--prime_p", help="Prime factor of n along with q", metavar='')
parser.add_argument("-q", "--prime_q", help="Prime factor of n along with p", metavar='')
parser.add_argument("-d", "--private_key", help="Private decryption key d", metavar='')
parser.add_argument("-e", "--public_key", help="Public key e used for encryption", metavar='')
parser.add_argument("-phi", "--modular_inverse", help="The modular inverse of p and q", metavar='')
args = parser.parse_args()
# ---------- End Add Arguments ---------- #

# ----------- Define Variables ------------ #
c, n, p, q, d, e, phi = None, None, None, None, None, None, None;
# ---------- End Define Variables ---------- #

# ----------- Parse Arguments ----------- #
given_info = ""
if args.cipher_text is not None:
    if not args.hex:
        c = int(args.cipher_text)
    else:
        c = int(args.cipher_text, 0)
    given_info += "c: " + str(c) + "\n"
if args.modulus_n is not None:
    if not args.hex:
        n = int(args.modulus_n)
    else:
        n = int(args.modulus_n, 0)
    given_info += "n: " + str(n) + "\n"
if args.prime_p is not None:
    if not args.hex:
        p = int(args.prime_p)
    else:
        p = int(args.prime_p, 0)
    given_info += "p: " + str(p) + "\n"
if args.prime_q is not None:
    if not args.hex:
        q = int(args.prime_q)
    else:
        q = int(args.prime_q, 0)
    given_info += "q: " + str(q) + "\n"
if args.private_key is not None:
    if not args.hex:
        d = int(args.private_key)
    else:
        d = int(args.private_key, 0)
    given_info += "d: " + str(d) + "\n"
if args.public_key is not None:
    if not args.hex:
        e = int(args.public_key)
    else:
        e = int(args.public_key, 0)
    given_info += "e: " + str(e) + "\n"
if args.modular_inverse is not None:
    if not args.hex:
        phi = args.modular_inverse
    else:
        phi = int(args.modular_inverse, 0)
    given_info += "φ: " + str(phi) + "\n"

# Get screen size for printing line
rows, columns = os.popen('stty size', 'r').read().split()
print "-" * int(columns)
print "GIVEN\n\n" + given_info[:-1]
print "-" * int(columns) + "\nGENERATED\n"
# ---------- End Parse Arguments ---------- #

# ---------- Define Functions ---------- #
def find_d(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi

    while e > 0:
        temp1 = temp_phi/e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2

        x = x2- temp1* x1
        y = d - temp1 * y1

        x2 = x1
        x1 = x
        d = y1
        y1 = y

    if temp_phi == 1:
        return d + phi

def checkFactorDB(n):
    r = requests.get('http://www.factordb.com/index.php?query=%i' % n)
    regex = re.compile("index\.php\?id\=([0-9]+)", re.IGNORECASE)
    ids = regex.findall(r.text)
    p_id = ids[1]
    q_id = ids[2]
    regex = re.compile("value=\"([0-9]+)\"", re.IGNORECASE)
    r_1 = requests.get('http://www.factordb.com/index.php?id=%s' % p_id)
    r_2 = requests.get('http://www.factordb.com/index.php?id=%s' % q_id)
    temp_p = int(regex.findall(r_1.text)[0])
    temp_q = int(regex.findall(r_2.text)[0])
    return (temp_p, temp_q)

def floorSqrt(n):
        x = n
        y = (x + 1) // 2
        while y < x:
            x = y
            y = (x + n // x) // 2
        return x

def isLastDigitPossibleSquare(x):
    if(x < 0):
        return False
    lastDig = x & 0xF
    if(lastDig > 9):
        return False
    if(lastDig < 2):
        return True
    if(lastDig == 4 or lastDig == 5 or lastDig == 9):
        return True
    return False

def fermatAttack(N,limit=100000):
    a = floorSqrt(N)+1
    b2 = a*a - N
    for i in range(limit):
        if(isLastDigitPossibleSquare(b2)):
            b = floorSqrt(b2)
            if(b**2 == a*a-N):
                p = a+b
                q = a-b
                print "p: " + str(p) + "\nq: " + str(q)
                return
        a = a+1
        b2 = a*a-N
    if(i==limit-1):
        print("Fermat Iteration Limit Exceeded")

def brent(N):
    if N%2==0:
            return 2
    y,c,m = random.randint(1, N-1),random.randint(1, N-1),random.randint(1, N-1)
    g,r,q = 1,1,1
    while g==1:
            x = y
            for i in range(r):
                    y = ((y*y)%N+c)%N
            k = 0
            while (k<r and g==1):
                    ys = y
                    for i in range(min(m,r-k)):
                            y = ((y*y)%N+c)%N
                            q = q*(abs(x-y))%N
                    g = gcd(q,N)
                    k = k + m
            r = r*2
    if g==N:
            while True:
                    ys = ((ys*ys)%N+c)%N
                    g = gcd(abs(x-ys),N)
                    if g>1:
                            break
    return g

# ---------- End Define Functions ---------- #

# ---------- Solve For Missing Information ---------- #
while None in (c, n, p, q, d, e, phi):
    if c is not None and d is not None and n is not None:
        # Rare case when we have everything needed to decrypt right away so skip all else
        m = pow(c,d,n)
        print "Flag: " + str(hex(m)[2:-1].decode('hex'))
        print "-" * int(columns)
        exit()

    if p is not None and q is not None and n is None:
        # We have p and q we are solving for n
        n = (p * q)
        print "n: " + str(n)

    if p is None and q is None and n is not None:
        # We have n and we are solving for its prime factors p and q
        data = checkFactorDB(n)
        if data is not None:
            p = data[0]
            str(p).strip("(").strip("L")
            q = data[1]
            str(q).strip(")").strip("L")
            if str(p * q) == str(n):
                print "p: " + str(p) + "\nq: " + str(q)
            else:
                print "Invalid factors on FactorDB... Starting manual factoring..."
                fermatAttack(n)
                print "Starting Brute-Force Method..."
                brent(n)
        else:
            print "Not in FactorDB... Starting manual factoring..."
            fermatAttack(n)
            print "Starting Brute-Force Method..."
            brent(n)


    if p is None and q is not None and n is not None:
        # We have q and n and we are solving for p
        p = (n / q)
        print "p: " + str(p)

    if q is None and p is not None and n is not None:
        # We have p and n and we are solving for q
        q = (n / p)
        print "q: " + str(q)

    if phi is None and p is not None and q is not None:
        # We have p and q and we are solving for phi
        phi = ((p - 1) * (q - 1))
        print "φ: " + str(phi)

    if d is None and phi is not None and e is not None:
        # We have phi and e we are solving for d
        d = find_d(e, phi)
        print "d: " + str(d)
# -------- End Solve For Missing Information -------- #

# ---------- Decrypt ---------- #
print "-" * int(columns)
m = pow(int(str(c),10),int(str(d),10),int(str(n),10))
# -------- End Decrypt -------- #

# ---------- Confirm Information ---------- #
if int(((e * d) % phi)) is not 1:
    print "e, d, and φ cannot be confirmed. Exit."
    print "Error: " + str(int(((e * d) % phi))) + " != 1"
    exit()
print "Flag: " + str(hex(m)[2:-1].decode('hex'))
print "-" * int(columns)
# -------- End Confirm Information -------- #
