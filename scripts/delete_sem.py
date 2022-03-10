import posix_ipc

SEMAPHORE_NAME = '/mininet_host_clients'

sem = posix_ipc.Semaphore(SEMAPHORE_NAME, flags=posix_ipc.O_CREAT)
sem.unlink()
