import random
from tokenize import group

import gevent
from gevent import Greenlet
from gevent.queue import Queue

from charm.toolbox.ecgroup import ECGroup, ZR, G
from charm.toolbox.eccurve import prime192v1

from network.router import simple_router

try:
    from soln.avss import avss_share, avss_reconstruct
except ImportError:
    from core.avss import avss_share, avss_reconstruct

import warnings

group = ECGroup(prime192v1)

warnings.filterwarnings("ignore", category=DeprecationWarning)


def test_avss_share(N=4, t=1, g=None, secret=5, leader=None, seed=None):
    sid = 'sidA'
    rnd = random.Random(seed)

    if g is None:
        g = group.random(G)

    if leader is None:
        leader = rnd.randint(0, N - 1)
    sends, recvs = simple_router(N, seed=seed)
    threads = []
    leader_input = Queue(1)
    for i in range(N):
        input = leader_input.get if i == leader else None
        th = Greenlet(avss_share, sid, i, N, t, leader, input, g, recvs[i], sends[i])
        th.start()
        threads.append(th)

    leader_input.put(secret)
    gevent.joinall(threads)

    commitments = threads[0].value[0]
    shares = []
    for th in threads:
        shares.append(th.value[1])
    return commitments, shares


def test_avss_reconstruct(N=4, tol=1, seed=None):
    sid = 'sidA'
    sends, recvs = simple_router(N, seed=seed)

    g = group.random(G)
    secret = group.random(ZR)
    commitments, shares = test_avss_share(N, tol, g, secret)

    threads = []
    inputs = [Queue() for _ in range(N)]

    for i in range(N):
        t = Greenlet(avss_reconstruct, sid=sid, pid=i, N=N, t=tol, g=g, ipt=inputs[i].get, rec=recvs[i], send=sends[i])
        t.start()
        threads.append(t)

    for i in range(N):
        inputs[i].put((commitments, shares[i]))
    gevent.joinall(threads)

    for t in threads:
        assert t.value == secret
