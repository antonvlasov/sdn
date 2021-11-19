import requests
from typing import Optional
import ujson
import argparse
import time
import random


class Item():
    def __init__(self, name, price, is_offer=None):
        self.name = name
        self.price = price
        self.is_offer = is_offer
    name: str
    price: float
    is_offer: Optional[bool] = None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Send requests to ips in given range. Only IPs differing by last byte are supported.')
    parser.add_argument('-s', '--startip', type=str,
                        help='first ip address')
    parser.add_argument('-e', '--endip', type=str,
                        help='last ip address')
    args = parser.parse_args()

    # random.seed()

    addr = str(args.startip)
    addresses = [addr]
    while addr != args.endip:
        parts = addr.split('.')
        parts[3] = str(int(parts[3])+1)
        addr = '.'.join(parts)
        addresses.append(addr)

    item = Item("rei plushy", random.randrange(2048))
    print('starting with item {}', item.__dict__)
    time.sleep(30)
    while True:
        try:
            ip = addresses[random.randint(0, len(addresses)-1)]
            resp = requests.post("http://{}:8001/items/1".format(ip),
                                 data=ujson.dumps(item.__dict__))
            if resp.status_code != 200:
                print(resp.text)
                time.sleep(3)
                continue
            d = ujson.loads(
                resp.text)
            item.price = d["item_price"]
            print(item.__dict__)

            time.sleep(1)
        except:
            time.sleep(3)
            pass
