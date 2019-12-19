from __future__ import division
from __future__ import absolute_import

__copyright__ = "Copyright (C) 2019 Icerm"

__license__ = """
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

__doc__ = """
VSYSPY is a Python api wrapper for VSYS network.
VSYSPY is a recursive acronym for V SYStems Python.
"""

from vsyspy.setting import *

import logging

console = logging.StreamHandler()
console.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger().addHandler(console)


OFFLINE = False


def set_offline():
    global OFFLINE
    OFFLINE = True


def set_online():
    global OFFLINE
    OFFLINE = False


def is_offline():
    global OFFLINE
    return OFFLINE


from vsyspy.wrapper import Wrapper


def create_api_wrapper(node_host=DEFAULT_NODE, api_key=DEFAULT_API_KEY):
    return Wrapper(node_host, api_key)


from .chain import Chain


def testnet_chain(api_wrapper=create_api_wrapper(DEFAULT_TESTNET_NODE, DEFAULT_TESTNET_API_KEY)):
    return Chain(TESTNET_CHAIN, TESTNET_CHAIN_ID, ADDRESS_VERSION, api_wrapper)


def default_chain(api_wrapper=create_api_wrapper()):
    return Chain(DEFAULT_CHAIN, DEFAULT_CHAIN_ID, ADDRESS_VERSION, api_wrapper)


from .account import Account
from .contract import Contract, DataEntry

__all__ = [
    'Account', 'Chain', 'Wrapper', 'Contract', 'DataEntry', 'is_offline'
]
