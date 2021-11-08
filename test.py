from itertools import count
import gevent
import gevent.monkey
gevent.monkey.patch_all()
import threading

def countdown(n:int):
    while True:
        print(n)
        gevent.sleep(1)

if __name__ == '__main__':
    ql = threading.Thread(target=countdown,name='query loop', daemon=True,args=(5,))
    ql.start()
    print("started countdown")
    while True:
        gevent.sleep(0)
