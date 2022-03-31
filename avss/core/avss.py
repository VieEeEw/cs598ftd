from charm.toolbox.eccurve import prime192v1
from charm.toolbox.ecgroup import ECGroup, ZR

from core.rbc import RBC

_g = ECGroup(prime192v1)


class AVSS(RBC):
    def __init__(self, pid, N, t, leader, ipt, rec, send, g):
        super().__init__(pid, N, t, leader, rec, send)
        self.v = None
        if pid == leader:
            s = ipt()
            self.coeffs = [s] + [_g.random(ZR) for _ in range(t)]
            self.v = [g ** i for i in self.coeffs]
        self.g = g

    def pred(self, content):
        rec_v = content
        if self.leader == self.pid:
            for i in range(self.N):
                x = i + 1
                self.send(i, (
                    'SHARE', sum([co * term for co, term in zip(self.coeffs, [x ** k for k in range(self.t + 1)])])))
        while self.shared is None:
            self.rec_msg()
        temp = rec_v[0]
        for i, term in enumerate(rec_v[1:]):
            temp *= term ** ((self.pid + 1) ** (i + 1))
        return self.g ** self.shared == temp

    def share(self):
        rv = self.rbc(lambda: self.v)
        return rv, self.shared


def avss_share(sid, pid, N, t, leader, ipt, g, rec, send):
    """Asynchronous Verifiable Secret Sharing

    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int t: maximum number of malicious nodes , ``N >= 3t + 1``
    :param int leader: ``0 <= leader < N``
    :param ipt: if ``pid == leader``, then :func:`input()` is called
        to wait for the input value
    :param group g: a generator of the elliptic curve group
    :param rec: :func:`receive()` blocks until a message is
        received; message is of the form::

            (i, (tag, ...)) = receive()
    :param send: sends (without blocking) a message to a designed
        recipient ``send(i, (tag, ...))``

    :return commitments and share
    """
    protocol = AVSS(pid, N, t, leader, ipt, rec, send, g)
    return protocol.share()


def avss_reconstruct(sid, pid, N, t, g, ipt, rec, send) -> ZR:
    """Asynchronous Verifiable Secret Sharing
    
    :param string sid: session id
    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int t: maximum number of malicious nodes , ``N >= 3t + 1``
    :param group g: a generator of the elliptic curve group
    :param ipt: func:`input()` is called to wait for the input value
    :param rec: :func:`receive()` blocks until a message is
        received; message is of the form::
            (i, (tag, ...)) = receive()
    :param send: sends (without blocking) a message to a designed
        recipient ``send(i, (tag, ...))``

    :return reconstructed secret 
    """
    v, p_prime = ipt()
    for i in range(N):
        send(i, ("REC", p_prime))
    shs = {}
    while True:
        sender, ctnt = rec()
        tag, p_sender = ctnt
        if tag != 'REC':
            continue
        temp = v[0]
        for i, term in enumerate(v[1:]):
            temp *= term ** ((sender + 1) ** (i + 1))
        if g ** p_sender != temp:
            continue
        shs[sender + 1] = p_sender
        if len(shs) == t + 1:
            shs_items = [(_g.init(ZR, xi), yi) for xi, yi in shs.items()]
            p0 = None
            # Interpolation
            for xi, yi in shs_items:
                for xj, _ in shs_items:
                    if xi == xj:
                        continue
                    term = yi * xj * ~(xj - xi)
                    p0 = p0 + term if p0 is not None else term
            return p0
