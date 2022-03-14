import posix_ipc

SEM_NAMES = ['/mininet_host_clients', '/two_nodes']

for sn in SEM_NAMES:
    sem = posix_ipc.Semaphore(sn, flags=posix_ipc.O_CREAT)
    sem.unlink()
