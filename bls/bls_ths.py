from shamir import gen_share, interpolate_at_0
from utils import Fp, random_fp, bls12_381, G1, sha256, hash_to_G2, G2


# TODO: To generate a secret key shares of each node and the threshold public keys of every node
# INPUT:: n: total number of nodes; t: fault threshold
# OUTPUT:: bls public key; [threshold secret keys]; [threshold public keys]
# NOTE: Although this function is also returning a list of private keys, in practice the key generation
# protocol will only return the i-th secret share to i-th node.  
def generate_bls_ths_keys(n: int, t: int) -> 'tuple[bls12_381.G1, list[(int, Fp)], list[(int, bls12_381.G1)]]':
    private = random_fp()
    public = bls12_381.multiply(G1, private.n)
    thd_pri = gen_share(n, t, private)
    thd_pub = [(i, bls12_381.multiply(G1, p.n)) for i, p in thd_pri]

    return public, thd_pri, thd_pub


# TODO: To generate a partial signature on the message
# INPUT:: msg: the message, tsk: threshold secret key
# OUTPUT:: partial signature on the message
def partial_sign(msg: str, tsk: 'tuple[int, Fp]') -> 'tuple[int, bls12_381.G2]':
    if type(msg) is bytes:
        msg = msg.decode()
    hg2 = hash_to_G2(msg.encode(), b'', sha256)
    i, si = tsk
    return i, bls12_381.multiply(hg2, si.n)


# TODO: To aggregate a list of parital signatures
# INPUT:: msg: the message; [threshold keys of every node]; [partial signatures]
# OUTPUT:: the bls signature on the message
# NOTE: Some of the partial signatures may be potentially invalid. 
# Perform explicit checks to eliminate invalid partial signatures
def aggregate_signature(msg: str, tpks: 'list[(int, bls12_381.G1)]',
                        signs: 'list[(int, bls12_381.G2)]') -> bls12_381.G2:
    d_tpks = dict(tpks)
    d_signs = dict(signs)
    zipped = [(k, pk, d_signs[k]) for k, pk in d_tpks.items() if k in d_signs]
    valid_shares = [(i, sign) for i, pk, sign in zipped if verify(msg, sign, pk)]
    return interpolate_at_g0(valid_shares)


# TODO: Verify the aggregated signature
def verify(msg: str, sign: bls12_381.G2, pk: bls12_381.G1) -> bool:
    if type(msg) is bytes:
        msg = msg.decode()
    hg2 = hash_to_G2(msg.encode(), b'', sha256)
    return bls12_381.pairing(sign, G1) == bls12_381.pairing(hg2, pk)


# TODO: Interpolate in the exponent at 0, i.e., compute G2^{P(0)}
# where P(x) is the polynomial defined by the shares
# INPUT:: shares: a list of tuples [(1,G2^a), (2,G2^b), (4,G2^c)] and index j
# OUTPUT:: G2^P(0): here P(x) is the polynomial defined by the shares
# NOTE: You need to work with `Fp = FiniteField(bls12_381.curve_order, 1)` for this function
def interpolate_at_g0(shares: 'list[(int, bls12_381.G2)]') -> bls12_381.G2:
    shs = [(Fp(x), y) for x, y in shares]
    p0 = None
    for i, (xi, yi) in enumerate(shs):
        term = Fp(1)
        div = Fp(1)
        for xj, _ in shs[:i]:
            term *= (-xj)
            div *= (xi - xj)
        for xj, _ in shs[i + 1:]:
            term *= (-xj)
            div *= (xi - xj)
        term /= div
        nt = bls12_381.multiply(yi, term.n)
        p0 = bls12_381.add(p0, nt) if p0 is not None else nt
    return p0


if __name__ == '__main__':
    def poly(x):
        t1 = bls12_381.multiply(G2, 2 * x.n)
        temp = bls12_381.add(t1, G2)
        t2 = bls12_381.multiply(G2, 5 * x.n ** 2)
        return bls12_381.add(temp, t2)


    def poly1(x):
        return Fp(114) + Fp(10) * Fp(x) ** 2 + Fp(20) * Fp(x)


    inter = [(1, poly(Fp(1))), (2, poly(Fp(2))), (3, poly(Fp(3)))]
    # inter = [(2, poly1(2)), (4, poly1(4)), (6, poly1(6))]
    res = interpolate_at_g0(inter)
    print(res)
    assert interpolate(gen_share(20, 7, 114514)) == 114514
    assert res == G2
