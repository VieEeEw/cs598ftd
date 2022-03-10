import random

import bls
import bls_ths
from utils import Fp, bls12_381, multiply, G1, G2
import shamir


# test_keygen tests whether the key generation process is followed correctly or not
def test_keygen():
    sk, pk = bls.generate_bls_keys()
    assert (pk == multiply(G1, sk.n))
    print("test_keygen successful")


# test_bls signs a message and then verifies the signature. It also test the signature with a differnt message
def test_bls():
    sk, pk = bls.generate_bls_keys()
    msg = str.encode("hello")
    sigma = bls.sign(msg, sk)
    assert (bls.verify(msg, sigma, pk))
    msg = str.encode("world")
    assert (not bls.verify(msg, sigma, pk))
    print("test_bls successful")


def test_bls_ths_keygen():
    # Feel free to write your own test case (NOT MANDETORY for homework)
    bls_ths.generate_bls_ths_keys(10, 3)


def test_bls_ths():
    # Feel free to write your own test case (NOT MANDETORY for homework)
    public, thd_pri, thd_pub = bls_ths.generate_bls_ths_keys(10, 3)
    msg = "I'm a message"
    signs = [bls_ths.partial_sign(msg, tsk) for tsk in thd_pri]
    # zipped = random.sample(list(zip(signs, thd_pub)), 10)
    # sign, pub = zip(*zipped)
    sign, pub = signs, thd_pub
    print(bls_ths.verify(msg, bls_ths.aggregate_signature(msg, pub, sign), public))


if __name__ == "__main__":
    test_bls_ths()
