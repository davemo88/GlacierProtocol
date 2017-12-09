import hashlib, subprocess, json, binascii, os, random, string
from functools import reduce

import base58

class BitcoinCli:
    CLIBIN = "bitcoin-cli"
    WIFPREFIX = "80"

    def __init__(self, datadir, cli_bin_path='', account=None, require_tmpfs=True):
        assert os.path.exists(datadir)
        self.datadir = datadir
        if require_tmpfs:
            self._require_tmpfs()
        
        self._bin = os.path.join(cli_bin_path, self.CLIBIN)

        self.account = str(random.randint(0,2**20)) if not account else account
## require specific account or an empty random account
        assert account or not self.get_addr_priv_key_pairs() 

    def __call__(self, command, *args):
        cliargs = ' '.join(map(str,args))
        cmd = "{} -datadir={} {} {}".format(self._bin, self.datadir, command, cliargs)
        results = subprocess.check_output(cmd,shell=True).decode().strip()
        try:
            results = json.loads(results)
        except ValueError:
            pass
        return results

    def create_utx(self, funding_txs, vouts, address_amounts):
        inputs = self._quote(json.dumps([{'txid':ftx['txid'],'vout':vouts[ftx['txid']]} for ftx in funding_txs]))
        outputs = self._quote(json.dumps({address:amount for address,amount in address_amounts}))
        utx = self('createrawtransaction', inputs, outputs)
        return utx

    def sign_tx(self, tx, funding_txs, vouts, redeem_script, signing_pk):
# does this need to be quoted?
#        tx = self._quote(tx)
        input_arg = self._quote(json.dumps([{
                                 'txid':funding_tx['txid'],
                                 'vout':vouts[funding_tx['txid']],
                                 'scriptPubKey':funding_tx['vout'][vouts[funding_tx['txid']]]['scriptPubKey']['hex'],
                                 'redeemScript':redeem_script} for funding_tx in funding_txs]))
        pk_arg = self._quote(json.dumps([signing_pk]))
        stx = self('signrawtransaction', tx, input_arg, pk_arg)
        return stx

    def import_wif_pk(self, wif_pk, rescan='false'):
        self("importprivkey", wif_pk, self.account, rescan)
    
    def get_addr_priv_key_pairs(self):
        addresses = self("getaddressesbyaccount", self.account)
        pairs = {addr: self("dumpprivkey", addr) for addr in addresses}
        return pairs
    
    def create_multisig(self, n, m, *addresses):
        assert len(addresses) == n
        assert m <= n
        account_addresses = self("getaddressesbyaccount", self.account)
        try:
            for addr in addresses:
                assert addr in account_addresses
        except AssertionError:
            raise AssertionError('address {} is not in your account - look out!')
    
        multi = self("createmultisig", m, self._quote(json.dumps(addresses)))
        multi['constituent_addresses'] = addresses
        multi['n'] = n
        multi['m'] = m
        json.dump(multi,open('multi-{}.json'.format(multi['address']),'w'))
        print('saved {}/multi-{}.json'.format(os.getcwd(), multi['address']))
        return multi

    def create_address(self, *hex_seeds):
## must be even length
        hex_pk = self._create_hex_pk(*hex_seeds)
        wif_pk = self._hex_to_wif_pk(hex_pk)
        self.import_wif_pk(wif_pk)

    def seed_addresses(self, *hex_seeds):
        for seed in hex_seeds:
            urand = binascii.hexlify(os.urandom(int(len(seed)/2))).decode()
            self.create_address(seed,urand)

    def _create_hex_pk(self, *hex_seeds):
        hashes = [int(hashlib.sha256(seed.encode()).hexdigest(),16) for seed in hex_seeds] 
        xored = reduce(lambda x,y: x ^ y, hashes)
        hexed = "{:x}".format(xored)
        if len(hexed) % 2:
            hexed = hexed[:-1]
        return hexed

    def _checksum(self, prefixed_key):
## unhex and hash twice
        unhexed = binascii.unhexlify(prefixed_key)
        hashed = hashlib.sha256(hashlib.sha256(unhexed).digest()).hexdigest()
## first 4 bytes
        checksum = hashed[:8]
        return checksum

    def _prefix(self, hex_pk):
## prefix 0x80 byte for bitcoin, 0xb4 for namecoin
        return self.WIFPREFIX + hex_pk
    
    def _hex_to_wif_pk(self, hex_pk):
        prefixed_key = self._prefix(hex_pk)
        checksummed_key = prefixed_key + self._checksum(prefixed_key) 
## unhex again and encode binary data ?
        wif = base58.encode(binascii.unhexlify(checksummed_key))
        
        return wif

    def _wif_to_hex_pk(self, wif_pk):
        checksummed_pk = binascii.hexlify(base58.decode(wif_pk)).decode()
## drop prefix byte and checksum
        hex_pk = checksummed_pk[2:-8]
        
        return hex_pk
    
    def _quote(self, cliarg):
        return "'{}'".format(cliarg)

    def _require_tmpfs(self):
        df_out = subprocess.check_output("df -T {} ".format(self.datadir),shell=True).decode().strip().splitlines()
## headers and one row
## filesystem type is second column
        fs_type = df_out[-1].split()[1].strip()
        assert fs_type == 'tmpfs'

class NamecoinCli(BitcoinCli):
    CLIBIN = 'namecoin-cli'
    WIFPREFIX = 'B4'

class BitcoinCashCli(BitcoinCli):
    pass
