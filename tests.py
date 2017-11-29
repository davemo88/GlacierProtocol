import pytest

import random, os, binascii

import multisig




def test_create_wif_pk(*args):

    pk_seeds = [
        ['54be3f'],
        ['abcdefg','1234567'],
        ['bf7538482d4','9915ba6933f','85fbe547dd3'],
        ['allsajflsfsafsa'],
        ['this00','could0','be0000','a00000','brain0','wallet'],
        random.sample(['this00','could0','be0000','a00000','brain0','wallet'], 6),
        [binascii.hexlify(os.urandom(62)).decode(), binascii.hexlify(os.urandom(62)).decode()]
            ]

    for seed in pk_seeds:
        print('\nseed:',seed)
        pk = multisig.create_hex_pk(*seed)
        print('pk:',pk)
        wif = multisig.hex_to_wif_pk(pk)
        print('wif pk:',wif)

def test_create_multisig(*args):
    m = 3
    n = 6
    for _ in range(n):
        seeds = [binascii.hexlify(os.urandom(16)).decode() for _ in range(2)]
        multisig.create_address(*seeds)
    multisig.get_addr_priv_key_pairs()
     
