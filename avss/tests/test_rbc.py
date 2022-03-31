import random
from collections import defaultdict
from random import getrandbits, sample

import gevent
from gevent import Greenlet
from gevent.queue import Queue

from core.rbc import reliablebroadcast
from network.router import simple_router


def malibroadcast(sid, pid, N, t, leader, input, predicate, receive, send, tid, case):
    def multicast(o):
        msg_type, _ = o
        if tid == 0:
            if pid == leader and msg_type == "PROPOSE":
                return
        elif tid == 1:
            if pid == leader and msg_type == "PROPOSE":
                if case == 0:
                    # if send > 2t + 1 proposals
                    for i in range(2 * t + 1):
                        send(i, o)
                    return
                else:
                    # if send < 2t + 1 proposals
                    for i in range(2 * t):
                        send(i, o)
                    return
        elif tid == 2:
            if pid == leader and msg_type == "PROPOSE":
                if case == 0:
                    # if > 2t + 1 get benign msg
                    for i in range(N):
                        if i < 2 * t + 1:
                            send(i, o)
                        else:
                            send(i, ("PROPOSE", b"malicious msg from mali broadcaster !!"))
                    return
                else:
                    # if > 2t + 1 get malicious msg
                    for i in range(N):
                        if i < 2 * t + 1:
                            send(i, ("PROPOSE", b"malicious msg from mali broadcaster !!"))
                        else:
                            send(i, o)
                    return
        elif tid == 3:
            if getrandbits(1):
                for i in range(N):
                    send(i, ("PROPOSE", b"malicious proposal from mali node !!"))
        elif tid == 4:
            if msg_type == "ECHO" or msg_type == "READY":
                if getrandbits(1):
                    for i in range(N):
                        send(i, (msg_type, b"inconsistent msg from mali node !!"))
                    return
        for i in range(N):
            send(i, o)

    if pid == leader:
        m = input()  # block until an input is received
        multicast(("PROPOSE", m))

    ready_snt = False
    echo_recvd, ready_recvd = defaultdict(set), defaultdict(set)

    while True:  # main receive loop
        sender, (msg_type, M) = receive()

        if msg_type == 'PROPOSE' and sender == leader:
            if predicate(M):
                multicast(('ECHO', M))

        if msg_type == 'ECHO':
            echo_recvd[M].add(sender)
            if len(echo_recvd[M]) == 2 * t + 1 and not ready_snt:
                multicast(('READY', M))
                ready_snt = True

        if msg_type == 'READY':
            ready_recvd[M].add(sender)
            if len(ready_recvd[M]) == t + 1 and not ready_snt:
                multicast(('READY', M))
                ready_snt = True
            if len(ready_recvd[M]) == 2 * t + 1:
                return M


def test_rbc(N=4, t=1, msg=b"Hello!", leader=None, seed=None, tid=5, case=0):
    # Test everything when runs are OK
    # if seed is not None: print 'SEED:', seed
    if tid == 1 or tid == 2:
        print("########### Test R{}, case {} ###########".format(str(tid), str(case)))
    elif tid == 5:
        print("########## Test baseline ###########")
    else:
        print("########### Test R{} ###########".format(str(tid)))

    sid = 'sidA'
    rnd = random.Random(seed)

    if leader is None: leader = rnd.randint(0, N - 1)
    mali_nodes = sample([i for i in range(N) if i != leader], t)
    sends, recvs = simple_router(N, seed=seed)
    threads = []
    leader_input = Queue(1)

    def predicate(msg):
        return True

    if tid == 0 or tid == 1 or tid == 2:
        for i in range(N):
            input = leader_input.get if i == leader else None
            if i == leader:
                th = Greenlet(malibroadcast, sid, i, N, t, leader, input, predicate, recvs[i], sends[i], tid, case)
            else:
                th = Greenlet(reliablebroadcast, sid, i, N, t, leader, input, predicate, recvs[i], sends[i])
            th.start()
            threads.append(th)
    elif tid == 3 or tid == 4:
        for i in range(N):
            input = leader_input.get if i == leader else None
            if i in mali_nodes:
                th = Greenlet(malibroadcast, sid, i, N, t, leader, input, predicate, recvs[i], sends[i], tid, case)
            else:
                th = Greenlet(reliablebroadcast, sid, i, N, t, leader, input, predicate, recvs[i], sends[i])
            th.start()
            threads.append(th)
    else:
        for i in range(N):
            input = leader_input.get if i == leader else None
            th = Greenlet(reliablebroadcast, sid, i, N, t, leader, input, predicate, recvs[i], sends[i])
            th.start()
            threads.append(th)

    leader_input.put(msg)
    gevent.joinall(threads)

    for th in threads:
        print(th.value)
    assert [th.value for th in threads] == [msg] * N
