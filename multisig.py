


import hashlib, argparse, subprocess, json
from functools import reduce

from base58 import b58encode

import config

def sha256(s):
    m = hashlib.sha256()
    m.update(s)
    return m.hexdigest()

def create_address(*hex_seeds):
    hex_pk = create_hex_pk(*hex_seeds)
    wif_pk = hex_to_wif_pk(hex_pk)

def create_hex_pk(*hex_seeds):
    length = len(hex_seeds[0])
    for s in hex_seeds[1:]:
        if len(s) != length:
            raise ValueError("seeds must be same length")

    hashes = [int(sha256(seed.encode()),16) for seed in hex_seeds] 
    xor = reduce(lambda x,y: x ^ y, hashes)
    print(xor)
    return "{:0{}x}".format(xor, length)

def hex_to_wif_pk(hex_pk):
## prefix 0x80 byte
    prefixed_key = "80" + hex_pk
## hash twice
    hashed = sha256(sha256(prefixed_key.decode("hex")))
## prefix checksum 
    priv_key = prefixed_key + hashed[0:8]
    
    wif = b58encode(priv_key.decode("hex"))
    
    return wif

def import_wif_pk(wif_pk):
   subprocess.call(
           "bitcoin-cli importprivkey {} {}".format(wif_pk, config.ACCOUNT),
           shell=True)

def get_addr_priv_key_pairs():
    addresses = json.loads(subprocess.check_output(
           "bitcoin-cli getaddressesbyaccount {}".format(config.ACCOUNT),
           shell=True))

    for addr in addresses:
        priv_key = subprocess.check_output(
            "bitcoin-cli dumpprivkey {}".format(addr),
            shell=True)
        print("Address: {} Private Key: {}".format(addr, priv_key))
    
def create_multisig(n, m, *addresses):
    assert len(addresses) == n
    assert m <= n
    addresses_str = "[\"{}\"]".format("\",\"".join(addresses))
    address = json.loads(subprocess.check_output(
        "bitcoin-cli createmultisig {} {}".format(m,addresses_str)
        ))
    print(address)
    return address
