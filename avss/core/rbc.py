class RBC:
    def __init__(self, pid, N, t, leader, rec, send):
        self.pid = pid
        self.N = N
        self.t = t
        self.leader = leader
        self.rec = rec
        self.send = send
        self.shared = None
        self.voted = False
        self.msg_map = dict()
        self.ret = None

    def pred(self, content):
        return True

    def multicast(self, msg):
        for i in range(self.N):
            self.send(i, msg)

    def rec_msg(self):
        sender, msg = self.rec()
        tag, content = msg

        if tag == 'PROPOSE':
            if sender != self.leader:
                print("PROPOSE message from other than leader:", sender)
                return
            if not self.pred(content):
                print("Predicate not satisfied")
                return
            self.msg_map.setdefault(str(content), {'echo_cnt': 0, 'rdy_cnt': 0})
            self.multicast(("ECHO", content))
        elif tag == 'ECHO':
            serialized = str(content)
            self.msg_map.setdefault(serialized, {'echo_cnt': 0, 'rdy_cnt': 0})['echo_cnt'] += 1
            if not self.voted and self.msg_map[serialized]['echo_cnt'] == 2 * self.t + 1:
                self.multicast(("READY", content))
                self.voted = True
        elif tag == 'READY':
            serialized = str(content)
            self.msg_map.setdefault(serialized, {'echo_cnt': 0, 'rdy_cnt': 0})['rdy_cnt'] += 1
            rdy_cnt = self.msg_map[serialized]['rdy_cnt']
            if not self.voted and rdy_cnt == self.t + 1:
                self.multicast(("READY", content))
                self.voted = True
            if rdy_cnt == 2 * self.t + 1:
                self.ret = content
                return
        elif tag == 'SHARE':
            self.shared = content
        else:
            print("Tag name unrecognized: " + tag)

    def rbc(self, ipt):
        if self.pid == self.leader:
            m = ipt()  # block until an input is received
            self.multicast(("PROPOSE", m))

        self.msg_map = dict()
        while True:  # main receive loop
            self.rec_msg()
            if self.ret is not None:
                return self.ret


def reliablebroadcast(sid, pid, N, t, leader, ipt, predicate, rec, send):
    """
    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int t: maximum number of malicious nodes , ``N >= 3t + 1``
    :param int leader: ``0 <= leader < N``
    :param ipt: if ``pid == leader``, then :func:`input()` is called
        to wait for the input value
    :param rec: :func:`receive()` blocks until a message is
        received; message is of the form::
            (i, (tag, ...)) = receive()

        where ``tag`` is one of ``{"PROPOSE", "ECHO", "READY"}``
    :param send: sends (without blocking) a message to a designed
        recipient ``send(i, (tag, ...))``

    :return str: ``m``
    """

    protocol = RBC(pid, N, t, leader, rec, send)
    return protocol.rbc(ipt)
