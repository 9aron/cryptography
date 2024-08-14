# -*- coding: utf-8 -*-

import secrets

import math  # Use sqrt, floor
import functools # Use reduce (Python 2.5+ and 3.x)
from functools import *
from fractions import Fraction


class PublicKey:
    __slots__ = ("curve", "pub")

    def __init__(self, curve, pub):
        self.curve = curve
        self.pub = pub

    def __repr__(self):
        return f"PublicKey({self.curve.name}, ({self.pub.x}, {self.pub.y}))"

    def __getstate__(self):
        return self.curve, self.pub

    def __setstate__(self, state):
        self.curve, self.pub = state
    
    def compress_point(self):
        return (self.pub.x, self.pub.y % 2)


class PrivateKey:
    __slot__ = ("curve", "priv")

    def __init__(self, curve, priv):
        self.curve = curve
        self.priv = priv

    def __repr__(self):
        return f"PrivateKey({self.curve.name}, {self.priv})"

    def __getstate__(self):
        return self.curve, self.priv

    def __setstate__(self, state):
        self.curve, self.priv = state


def make_keypair(curve):
    priv = secrets.randbelow(curve.field.n)
    pub = priv * curve.g
    return PublicKey(curve, pub), PrivateKey(curve, priv)

