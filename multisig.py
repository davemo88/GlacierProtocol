import hashlib, argparse, subprocess, json, binascii, os, time
from functools import reduce

import base58

import config

def dump_tx_json(txid):
## requires internet or blockchain
    j = json.loads(subprocess.check_output(
        "bitcoin-cli getrawtransaction {} 1".format(txid),
        shell=True
        ).decode())
    with open('{}.json'.format(txid), 'w') as fp:
        json.dump(j,fp)

def create_signed_tx(input_txid, amount, vout, hex_script_pubkey, receiving_addr, redeem_script, *signing_pks):
    '''
    input_txid: txid for the tx to spend from
    vout: index of the output of the input tx we want to spend from. see the vout array in the tx json
    receiving_addr: address to spend to
    redeem_script: we are spending from a multisig address so we need this
    *signing_pks: array of private keys to sign tx. order matters?
    '''
    tx = create_utx(input_txid, amount, vout, receiving_addr) 
    for pk in signing_pks:
        tx = sign_tx(tx, vout, hex_script_pubkey, redeem_script, pk)
    return tx

def create_utx(input_txid, amount, vout, receiving_addr):
    input_arg = json.dumps([{'txid':input_txid,'vout':vout}])
    output_arg = json.dumps({receiving_addr:amount})    
    utx = subprocess.check_output(
        "bitcoin-cli createrawtransaction \'{}\' \'{}\'".format(input_arg, output_arg),
        shell=True).decode().strip()
    return utx

def sign_tx(tx, input_txid, vout, hex_script_pubkey, redeem_script, signing_pk):
    input_arg = json.dumps([{'txid':input_txid,
                             'vout':vout,
                             'scriptPubKey':hex_script_pubkey,
                             'redeemScript':redeem_script}])
    pk_arg = json.dumps([signing_pk])
    signed_tx = json.dumps(subprocess.check_output(
        "bitcoin-cli signrawtransaction \'{}\' \'{}\' \'{}\'".format(tx, input_arg, pk_arg),
        shell=True
        ).decode())
    return signed_tx

def multi_sig_from_rolls(*rolls,length=62):
    for roll in rolls:
        urand = binascii.hexlify(os.urandom(31)).decode()
        print('roll:',roll)
        print('urand:',urand)
        create_address(roll,urand)

def create_address(*hex_seeds):
    print('creating hx pk')
    hex_pk = create_hex_pk(*hex_seeds)
    print('creating wif pk')
    wif_pk = hex_to_wif_pk(hex_pk)
    print('importing wif pk')
    import_wif_pk(wif_pk)

def create_hex_pk(*hex_seeds):
    length = len(hex_seeds[0])
    for s in hex_seeds[1:]:
        if len(s) != length:
            raise ValueError("seeds must be same length")

    hashes = [int(hashlib.sha256(seed.encode()).hexdigest(),16) for seed in hex_seeds] 
    xor = reduce(lambda x,y: x ^ y, hashes)
#    print(xor)
#    try:
#        assert '{:x}'.format(xor) == "{:0{}x}".format(xor, length)
#    except AssertionError:
#        nopadding = '{:x}'.format(xor)
#        padding = "{:0{}x}".format(xor, length)
#        print('padding({}):{}'.format(len(padding),padding))
#        print('nopadding({}):{}'.format(len(nopadding),nopadding))
#        raise AssertionError('they don\'t match :(')
## convert to hex
    hexed = "{:x}".format(xor, length)
#    assert len(hexed) % 2
    assert len(hexed) % 2 == 0 
    return hexed
#    return "{:0{}x}".format(xor, length)

def hex_to_wif_pk(hex_pk):
## should figure out hex vs bytes significance for encoding / hashing
## prefix 0x80 byte
    prefixed_key = "80" + hex_pk
## unhex and hash twice
    unhexed = binascii.unhexlify(prefixed_key)
    hashed = hashlib.sha256(hashlib.sha256(unhexed).digest()).hexdigest()
## append checksum 
    checksummed_key = prefixed_key + hashed[0:8]
## unhex again and encode binary data ?
    wif = base58.encode(binascii.unhexlify(checksummed_key))
    
    return wif

def import_wif_pk(wif_pk, label='\'\'', rescan='false'):
    print("bitcoin-cli importprivkey {} {} {}".format(wif_pk, label, rescan))
    subprocess.call(
           "bitcoin-cli importprivkey {} {} {}".format(wif_pk, label, rescan),
           shell=True)

def get_addr_priv_key_pairs(account=config.ACCOUNT):
    addresses = json.loads(subprocess.check_output(
           "bitcoin-cli getaddressesbyaccount {}".format(account),
           shell=True).decode())

    pairs={}
    for addr in addresses:
## remove newline at end of key
        priv_key = subprocess.check_output(
            "bitcoin-cli dumpprivkey {}".format(addr),
            shell=True)[:-1].decode()
        pairs[addr]=priv_key 
    return pairs

def create_multisig(n, m, *addresses, account_name=''):
    assert len(addresses) == n
    assert m <= n
    account_addresses = json.loads(subprocess.check_output(
           "bitcoin-cli getaddressesbyaccount {}".format(config.ACCOUNT),
           shell=True))
    try:
        for addr in addresses:
            assert addr in account_addresses
    except AssertionError:
        raise AssertionError('address {} is not in your account - look out!')

    addresses_str = "\'[\"{}\"]\'".format("\",\"".join(addresses))
    address = json.loads(subprocess.check_output(
        "bitcoin-cli createmultisig {} {}".format(m,addresses_str)
        ).decode())
    return address
