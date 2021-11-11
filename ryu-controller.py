import sys
from ryu.cmd import manager
# from gevent import monkey
# monkey.patch_all()


def main():
    sys.argv.append('--ofp-tcp-listen-port')
    sys.argv.append('6653')
    sys.argv.append(
        '/home/mininet/project/dynamic_routing.py')
    sys.argv.append('--observe-links')
    manager.main()


if __name__ == '__main__':
    main()
