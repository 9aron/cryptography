# -*- coding: utf-8 -*-

import secrets


class Keypair(object):
    def __init__(self, curve, priv=None, pub=None):
        if priv is None and pub is None:
            raise ValueError("Private and/or public key must be provided")
        self.curve = curve
        self.can_sign = True
        self.can_encrypt = True
        if priv is None:
            self.can_sign = False
        self.priv = priv
        self.pub = pub
        if pub is None:
            self.pub = self.priv * self.curve.g

    def get_ecdh_secret(self, other_keypair):
        # Don't check if both keypairs are on the same curve. Should raise a warning only
        if self.can_sign and other_keypair.can_encrypt:
            secret = self.priv * other_keypair.pub
        elif self.can_encrypt and other_keypair.can_sign:
            secret = self.pub * other_keypair.priv
        else:
            raise ValueError("Missing crypto material to generate DH secret")
        return secret


def make_keypair(curve):
    priv = secrets.randbelow(curve.field.n)
    pub = priv * curve.g
    return Keypair(curve, priv, pub)

