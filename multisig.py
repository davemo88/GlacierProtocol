import hashlib, subprocess, json, binascii, os
from functools import reduce

import base58

import config

def dump_tx_json(txid):
## requires internet or blockchain
    j = json.loads(subprocess.check_output(
        "bitcoin-cli -datadir={} getrawtransaction {} 1".format(config.DATADIR, txid),
        shell=True
        ).decode())
    with open('{}.json'.format(txid), 'w') as fp:
        json.dump(j,fp)

def get_spend_params(spend_json):
    '''
    spend_json: path json file like:
    {
        'funding_tx': json tx used for funding the spend. generate with getrawtransaction or decoderawtransaction
        'amount': amount to spend. REST WILL BE USED FOR FEE ! ! ! (could also be sent to other addresses)
        'vout': index of output of funding_tx to spend from
        'receiving_address': address to spend to
    }
    '''
    spend_info = json.load(open(spend_json,'r'))

    vout = spend_info['vout']
    amount = spend_info['amount']
    receiving_address = spend_info['receiving_address']
    funding_tx = spend_info['funding_tx'] 

    funding_txid = funding_tx['txid']
    hex_script_pubkey = funding_tx['vout'][vout]['scriptPubKey']['hex']

    return funding_txid, amount, vout, hex_script_pubkey, receiving_address

def create_signed_tx(funding_txid, amount, vout, hex_script_pubkey, receiving_addr, redeem_script, *signing_pks):
    '''
    funding_txid: txid for the tx to spend from
    vout: index of the output of the input tx we want to spend from. see the vout array in the tx json
    receiving_addr: address to spend to
    redeem_script: we are spending from a multisig address so we need this
    *signing_pks: array of private keys to sign tx. order matters?
    '''
    tx = create_utx(funding_txid, amount, vout, receiving_addr) 
    for pk in signing_pks:
        tx = sign_tx(tx, vout, hex_script_pubkey, redeem_script, pk)
    return tx

def create_utx(funding_txid, amount, vout, receiving_addr):
    input_arg = json.dumps([{'txid':funding_txid,'vout':vout}])
    output_arg = json.dumps({receiving_addr:amount})    
    utx = subprocess.check_output(
        "bitcoin-cli -datadir={} createrawtransaction \'{}\' \'{}\'".format(config.DATADIR, input_arg, output_arg),
        shell=True).decode().strip()
    return utx

def sign_tx(tx, funding_txid, vout, hex_script_pubkey, redeem_script, signing_pk):
    input_arg = json.dumps([{'txid':funding_txid,
                             'vout':vout,
                             'scriptPubKey':hex_script_pubkey,
                             'redeemScript':redeem_script}])
    pk_arg = json.dumps([signing_pk])
    signed_tx = json.loads(subprocess.check_output(
        "bitcoin-cli -datadir={} signrawtransaction \'{}\' \'{}\' \'{}\'".format(config.DATADIR, tx, input_arg, pk_arg),
        shell=True).decode())
    return signed_tx

def from_rolls(*rolls,length=62):
    for roll in rolls:
        assert len(roll)==length and len(roll) % 2 == 0
        urand = binascii.hexlify(os.urandom(int(length/2))).decode()
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
    hexed = "{:x}".format(xor)
# need an even length string
    if len(hexed) % 2:
        hexed = hexed[:-1]
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
    print("bitcoin-cli -datadir={} importprivkey {} {} {}".format(config.DATADIR, wif_pk, label, rescan))
    subprocess.call(
           "bitcoin-cli -datadir={} importprivkey {} {} {}".format(config.DATADIR, wif_pk, label, rescan),
           shell=True)

def get_addr_priv_key_pairs(account=config.ACCOUNT):
    addresses = json.loads(subprocess.check_output(
           "bitcoin-cli -datadir={} getaddressesbyaccount {}".format(config.DATADIR, account),
           shell=True).decode())

    pairs={}
    for addr in addresses:
## remove newline at end of key
        priv_key = subprocess.check_output(
            "bitcoin-cli -datadir={} dumpprivkey {}".format(config.DATADIR, addr),
            shell=True)[:-1].decode()
        pairs[addr]=priv_key 
    return pairs

def create_multisig(n, m, *addresses, account_name=''):
    assert len(addresses) == n
    assert m <= n
    account_addresses = json.loads(subprocess.check_output(
           "bitcoin-cli -datadir={} getaddressesbyaccount {}".format(config.DATADIR, config.ACCOUNT),
           shell=True).decode())
    try:
        for addr in addresses:
            assert addr in account_addresses
    except AssertionError:
        raise AssertionError('address {} is not in your account - look out!')

    addresses_str = "\'[\"{}\"]\'".format("\",\"".join(addresses))
    multi = json.loads(subprocess.check_output(
        "bitcoin-cli -datadir={} createmultisig {} {}".format(config.DATADIR, m, addresses_str),
        shell=True).decode())
    multi['constituent_addresses'] = addresses
    multi['n'] = n
    multi['m'] = m
    json.dump(multi,open('multi-{}.json'.format(multi['address'])))
    return multi
