import hashlib, subprocess, json, binascii, os, random, string
from functools import reduce

import base58

import config

class BitcoinCli:
    CLIBIN = "bitcoin-cli"

    def __init__(self, datadir, account=None):
        self.datadir = datadir
        self.account = str(random.randint(0,2**20)) if not account else account
        assert os.path.exists(datadir)
        assert account or not self.get_addr_priv_key_pairs() 

    def __call__(self, command, *args):
        cliargs = ' '.join(map(str,args))
        cmd = "{} -datadir={} {} {}".format(self.CLIBIN, self.datadir, command, cliargs)
#        print(command, args, cmd)
        results = subprocess.check_output(cmd,shell=True).decode().strip()
        try:
            results = json.loads(results)
        except json.decoder.JSONDecodeError:
            pass
        return results

    def create_utx(self, funding_tx, amount, vout, receiving_addr):
        input_arg = self._quote(json.dumps([{'txid':funding_tx['txid'],'vout':vout}]))
        output_arg = self._quote(json.dumps({receiving_addr:amount}))
#        utx = subprocess.check_output(
#            "bitcoin-cli -datadir={} createrawtransaction \'{}\' \'{}\'".format(config.DATADIR, input_arg, output_arg),
#            shell=True).decode().strip()
        utx = self('createrawtransaction', input_arg, output_arg)
        return utx

    def sign_tx(self, tx, funding_tx, vout, redeem_script, signing_pk):
        tx = self._quote(tx)
        input_arg = self._quote(json.dumps([{'txid':funding_txid['txid'],
                                 'vout':vout,
                                 'scriptPubKey':funding_tx['vout'][vout]['scriptPubKey']['hex'],
                                 'redeemScript':redeem_script}]))
        pk_arg = self._quote(json.dumps([signing_pk]))
        stx = self('signrawtransaction', tx, input_arg, pk_arg)
#        signed_tx = json.loads(subprocess.check_output(
#            "bitcoin-cli -datadir={} signrawtransaction \'{}\' \'{}\' \'{}\'".format(config.DATADIR, tx, input_arg, pk_arg),
#            shell=True).decode())
        return signed_tx

    def import_wif_pk(self, wif_pk, rescan='false'):
        self("importprivkey", wif_pk, self.account, rescan)
#        subprocess.call(
#               "bitcoin-cli -datadir={} importprivkey {} {} {}".format(config.DATADIR, wif_pk, label, rescan),
#               shell=True)
    
    def get_addr_priv_key_pairs(self):
        addresses = self("getaddressesbyaccount", self.account)
#        addresses = json.loads(subprocess.check_output(
#               "bitcoin-cli -datadir={} getaddressesbyaccount {}".format(config.DATADIR, account),
#               shell=True).decode())
    
        pairs={}
        for addr in addresses:
    ## remove newline at end of ke
            priv_key = self("dumpprivkey", addr)
#            priv_key = subprocess.check_output(
#                "bitcoin-cli -datadir={} dumpprivkey {}".format(config.DATADIR, addr),
#                shell=True)[:-1].decode()
            pairs[addr] = priv_key 
        return pairs
    
    def create_multisig(self, n, m, *addresses):
        assert len(addresses) == n
        assert m <= n
        account_addresses = self("getaddressesbyaccount", self.account)
#        account_addresses = json.loads(subprocess.check_output(
#               "bitcoin-cli -datadir={} getaddressesbyaccount {}".format(config.DATADIR, config.ACCOUNT),
#               shell=True).decode())
        try:
            for addr in addresses:
                assert addr in account_addresses
        except AssertionError:
            raise AssertionError('address {} is not in your account - look out!')
    
#        addresses_str = "\'[\"{}\"]\'".format("\",\"".join(addresses))
        multi = self("createmultisig", m, self._quote(json.dumps(addresses)))
#        multi = json.loads(subprocess.check_output(
#            "bitcoin-cli -datadir={} createmultisig {} {}".format(config.DATADIR, m, addresses_str),
#            shell=True).decode())
        multi['constituent_addresses'] = addresses
        multi['n'] = n
        multi['m'] = m
        json.dump(multi,open('multi-{}.json'.format(multi['address']),'w'))
        print('saved {}/multi-{}.json'.format(os.getcwd(), multi['address']))
        return multi

    def create_address(self, *hex_seeds):
        hex_pk = self._create_hex_pk(*hex_seeds)
        wif_pk = self._hex_to_wif_pk(hex_pk)
        self.import_wif_pk(wif_pk)

    def seed_addresses(self, *hex_seeds):
        for seed in hex_seeds:
            assert len(seed) % 2 == 0
            urand = binascii.hexlify(os.urandom(int(len(seed)/2))).decode()
    #        print('seed:',seed)
    #        print('urand:',urand)
            self.create_address(seed,urand)

    def _create_hex_pk(self, *hex_seeds):
        hashes = [int(hashlib.sha256(seed.encode()).hexdigest(),16) for seed in hex_seeds] 
        xor = reduce(lambda x,y: x ^ y, hashes)
        hexed = "{:x}".format(xor)
        if len(hexed) % 2:
            hexed = hexed[:-1]
        return hexed
    
    def _hex_to_wif_pk(self, hex_pk):
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
    
    def _quote(self, cliarg):
        return "'{}'".format(cliarg)

class NamecoinCli(BitcoinCli):
    CLIBIN = 'namecoin-cli'

class BitcoinCashCli(BitcoinCli):
    pass
