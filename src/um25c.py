# -*- coding: utf-8 -*-

import struct
import time
import datetime
import bluetooth

import config


def read_data(sock):
    sock.send(bytes([0xF0]))
    d = bytes()
    while len(d) < 130:
        d += sock.recv(1024)
    assert len(d) == 130, len(d)
    return d


def connect_to_usb_tester():
    sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
    sock.connect((config.MAC, 1))
    sock.settimeout(1.0)
    for _ in range(10):
        try:
            read_data(sock)
        except bluetooth.BluetoothError as e:
            time.sleep(0.2)
        else:
            break
    else:
        raise e
    return sock


def get_mwh_data(sock):

    d = b""
    while len(d) != 130:
        sock.send((0xF0).to_bytes(1, byteorder="big"))
        d += sock.recv(130)

    _, mwh = struct.unpack(">II", d[16 : 16 + 8])  # Skip mAh, unpack mWh

    # TODO return time with mwh
    return mwh



if __name__ == '__main__':
    sock = connect_to_usb_tester(config.MAC)

    while True:
        print(get_mwh_data(sock))
        time.sleep(1)

    sock.close()
