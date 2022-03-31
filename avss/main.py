from tests.test_rbc import test_rbc
from tests.test_avss import test_avss_share, test_avss_reconstruct


def test_rbc_main(N, t, seed, tid=5, case=0):
    test_rbc(N=N, t=t, msg=b'Welcome to CS598FTD', seed=seed, tid=tid, case=case)


def test_avss_main(N, t, seed):
    # print(test_avss_share(N=N, t=t, g=None, secret=5, seed=seed))
    print(test_avss_reconstruct(N, t, seed))


if __name__ == '__main__':
    # test_rbc_main(4, 1, None)
    test_avss_main(4, 1, None)
    # rbc tests
    # test_rbc_main(4, 1, None)

    # R0. A malicious broadcaster does not send anything
    # test_rbc_main(4, 1, None, 0)

    # R1. A malicious broadcaster sends the proposal to a subset of nodes
    # test_rbc_main(4, 1, None, 1, 0)     # if send > 2t + 1 proposals
    # test_rbc_main(4, 1, None, 1, 1)     # if send < 2t + 1 proposals

    # R2. A malicious broadcaster sends different proposals to different nodes
    # test_rbc_main(4, 1, None, 2, 0)     # if > 2t + 1 get benign msg
    # test_rbc_main(4, 1, None, 2, 1)     # if > 2t + 1 get malicious msg

    # R3. Malicious nodes pretend to be a broadcaster and send proposal to others.
    # test_rbc_main(4, 1, None, 3)

    # R4. Malicious nodes send ECHO and READY for inconsistent messages
    # test_rbc_main(4, 1, None, 4)

    # avss tests
    # test_avss_main(4, 1, None)
