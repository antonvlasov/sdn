import sqlite3
import pandas
from datetime import datetime


DB_PATH = "/home/mininet/project/data/logs.db"

FIELD_ID = "ID"
FIELD_TEST = "Test"
FIELD_SERVER = "Server"
FIELD_CLIENT = "Client"
FIELD_DESCRIPTION = "Description"
FIELD_RECEIVED_RESPONSES = "ReceivedResponses"
FIELD_TOTAL_REQUESTS = "TotalRequests"
FIELD_BYTES = "Bytes"
FIELD_REQUEST_TIMESTAMP = "RequestTimestamp"
FIELD_FIRST_RESPONSE_TIME = "FirstResponseTimestamp"
FIELD_LAST_RESPONSE_TIME = "LastResponseTimestamp"

KIND_FILE = 'file'
KIND_WEB = "web"
KIND_VIDEO = "video"


def count_speed(row):
    if row[FIELD_REQUEST_TIMESTAMP] == '' or row[FIELD_LAST_RESPONSE_TIME] == '':
        return 0

    parsed_start = datetime.strptime(
        " ".join(row[FIELD_REQUEST_TIMESTAMP].split()), '%b %d %H:%M:%S.%f')
    parsed_end = datetime.strptime(
        " ".join(row[FIELD_LAST_RESPONSE_TIME].split()), '%b %d %H:%M:%S.%f')

    duration = parsed_end-parsed_start
    bytes_second = row[FIELD_BYTES]/duration.total_seconds()

    Mbit_sec = bytes_second/(1024*1024)*8

    return Mbit_sec


def check_no_packets_dropped():
    query = f'\
        SELECT {FIELD_ID},{FIELD_TEST},{FIELD_SERVER},{FIELD_CLIENT},{FIELD_DESCRIPTION},{FIELD_RECEIVED_RESPONSES},{FIELD_TOTAL_REQUESTS},{FIELD_BYTES},{FIELD_REQUEST_TIMESTAMP},{FIELD_FIRST_RESPONSE_TIME},{FIELD_LAST_RESPONSE_TIME}\
        FROM logs\
        WHERE {FIELD_TEST} = (SELECT MAX({FIELD_TEST}) FROM logs);'

    con = sqlite3.connect(DB_PATH)

    df = pandas.read_sql(query, con)

    print("checking test", df[FIELD_TEST][0])

    lost_df = df[(df[FIELD_RECEIVED_RESPONSES] != df[FIELD_TOTAL_REQUESTS])]
    lost = (lost_df[FIELD_TOTAL_REQUESTS] -
            lost_df[FIELD_RECEIVED_RESPONSES]).sum()
    file_speed = df[(df[FIELD_DESCRIPTION] == KIND_FILE)
                    ].apply(count_speed, axis=1)
    web_speed = df[(df[FIELD_DESCRIPTION] == KIND_WEB)
                   ].apply(count_speed, axis=1)
    video_speed = df[(df[FIELD_DESCRIPTION] == KIND_VIDEO)
                     ].apply(count_speed, axis=1)

    print()
    print('requests with missing responses:', lost)
    if not file_speed.empty:
        print('file mean speed:', file_speed.mean(), 'Mbit/s')
    if not web_speed.empty:
        print('web mean speed:', web_speed.mean(), 'Mbit/s')
    if not video_speed.empty:
        print('video mean speed:', video_speed.mean(), 'Mbit/s')

    if lost == 0:
        print('PASS')
    else:
        print('FAIL')


if __name__ == '__main__':
    check_no_packets_dropped()
