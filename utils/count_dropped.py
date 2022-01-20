from typing import List, Dict
import os
import re
import collections
import ipaddress

RE_DEST = re.compile('http://(?P<dst>.+):6000/opinion')
RE_SRC = re.compile('recieved\smessage\sfrom\s(?P<src>.+):')
BASE_IP = ipaddress.IPv4Address('10.0.0.0')


def count_matching(lines, re):
    matches = [re.search(line) for line in lines]
    destinations = [match.group(1)
                    for match in matches if match is not None]
    grouped = collections.Counter(destinations)
    grouped = {ipaddress.IPv4Address(k): v for k, v in grouped.items()}
    return grouped


def count_dropped(log_path: str, count: int):
    sent_messages: Dict[ipaddress.IPv4Address,
                        Dict[ipaddress.IPv4Address, int]] = {}
    recieved_messages: Dict[ipaddress.IPv4Address,
                            Dict[ipaddress.IPv4Address, int]] = {}

    for i in range(1, count+1):
        client_log = os.path.join(log_path, f'client-{i}.log')
        server_log = os.path.join(log_path, f'server-{i}.log')

        with open(client_log) as file:
            lines = file.readlines()
            sent_messages[BASE_IP+i] = count_matching(lines, RE_DEST)

        with open(server_log) as file:
            lines = file.readlines()
            recieved_messages[BASE_IP+i] = count_matching(lines, RE_SRC)

    diffs: Dict[str, int] = {}
    for dst, msgs in recieved_messages.items():
        diff = 0
        for src, got in msgs.items():
            sent = sent_messages[src][dst]
            diff += sent-got
        diffs[dst.compressed] = diff
        if diff != 0:
            print(f'some dropped for {dst.compressed}')

    print(diffs)


if __name__ == '__main__':
    count_dropped('/home/mininet/project/data/logs', 40)
