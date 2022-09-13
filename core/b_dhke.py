"""
Implementation of https://gist.github.com/RubenSomsen/be7a4760dd4596d06963d67baf140406

Alice:
A = a*G
return A

Bob:
Y = hash_to_curve(secret_message)
r = random blinding factor
B'= Y + r*G
return B'

Alice:
C' = a*B'
  (= a*Y + a*r*G)
return C'

Bob:
C = C' - r*A
 (= C' - a*r*G)
 (= a*Y)
return C, secret_message

Alice:
Y = hash_to_curve(secret_message)
C == a*Y

If true, C must have originated from Alice
"""

import hashlib

from ecc.curve import Point, secp256k1
from ecc.key import gen_keypair

G = secp256k1.G


def hash_to_curve(secret_msg):
    """Generates x coordinate from the message hash and checks if the point lies on the curve.
    If it does not, it tries computing again a new x coordinate from the hash of the coordinate."""
    point = None
    msg = secret_msg
    while point is None:
        x_coord = int(hashlib.sha256(msg).hexdigest().encode("utf-8"), 16)
        y_coord = secp256k1.compute_y(x_coord)
        try:
            # Fails if the point is not on the curve
            point = Point(x_coord, y_coord, secp256k1)
        except:
            msg = str(x_coord).encode("utf-8")

    return point


def step1_bob(secret_msg):
    secret_msg = secret_msg.encode("utf-8")
    Y = hash_to_curve(secret_msg)
    r, _ = gen_keypair(secp256k1)
    B_ = Y + r * G
    return B_, r


def step2_alice(B_, a):
    C_ = a * B_
    return C_


def step3_bob(C_, r, A):
    C = C_ - r * A
    return C


def verify(a, C, secret_msg):
    Y = hash_to_curve(secret_msg.encode("utf-8"))
    return C == a * Y


### Below is a test of a simple positive and negative case

# # Alice private key
# a, A = gen_keypair(secp256k1)
# secret_msg = "test"
# B_, r = step1_bob(secret_msg)
# C_ = step2_alice(B_, a)
# C = step3_bob(C_, r, A)
# print("C:{}, secret_msg:{}".format(C, secret_msg))

# assert verify(a, C, secret_msg)
# assert verify(a, C + 1*G, secret_msg) == False  # adding 1*G shouldn't pass
