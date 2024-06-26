#!/usr/bin/env python3

""" Password encription"""

import bcrypt


def hash_password(password: str) -> bytes:
    """ Hash password """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Validate whether password is hashed"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
