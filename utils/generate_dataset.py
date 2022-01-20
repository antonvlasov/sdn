import pandas as pd
from typing import List, Dict, Tuple
from dataclasses import dataclass
import numpy as np
import os


# def generate(pairs_df: pd.DataFrame, dst_path: str, duration_secs: int, event_count: int, random_starts: bool):

#     res = pairs_df['number'].sample(
#         event_count, replace=True).to_frame().rename(columns={'number': 'numPair'})

#     if random_starts:
#         starts = np.random.randint(0, duration_secs, res.shape[0])
#         lifetimes = np.random.randint(0, duration_secs - starts)
#         res['start'] = starts
#         res['lifetime'] = lifetimes
#     else:
#         res['start'] = 0
#         res['lifetime'] = duration_secs

#     res['capacity'] = 1

#     res = res.sort_values('start')
#     res.to_csv(dst_path, index=False)


def generate_many():
    dst_dir = '/home/mininet/project/data/scenario/generated'
    duration = 600

    count_variants = [10, 100, 1000, 10000, 100000]
    for count in count_variants:
        generate_simple(os.path.join(
            dst_dir, f'prolonged_{count}.csv'), duration, count, False)
        generate_simple(os.path.join(
            dst_dir, f'randstart_{count}.csv'), duration, count, True)


def generate_simple(dst_path: str, duration_secs: int, event_count: int, random_starts: bool):

    pairs = np.full((event_count), 3)
    res = pd.DataFrame(pairs,
                       columns=['numPair'])
    if random_starts:
        starts = np.random.randint(0, duration_secs, res.shape[0])
        lifetimes = np.random.randint(0, duration_secs - starts)
        res['start'] = starts
        res['lifetime'] = lifetimes
    else:
        res['start'] = 0
        res['lifetime'] = duration_secs

    res['capacity'] = 1

    res = res.sort_values('start')
    res.to_csv(dst_path, index=False, sep=';')


if __name__ == '__main__':
    generate_many()
