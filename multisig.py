import hashlib, subprocess, json, binascii, os, random, string
from functools import reduce

import base58

class BitcoinCli:
    CLIBIN = "bitcoin-cli"
    WIFPREFIX = "80"

    def __init__(self, datadir, account=None, require_tmpfs=True):
        self.datadir = datadir
        self.account = str(random.randint(0,2**20)) if not account else account

        assert os.path.exists(datadir)
        if require_tmpfs:
            self._require_tmpfs()

        assert account or not self.get_addr_priv_key_pairs() 

    def __call__(self, command, *args):
        cliargs = ' '.join(map(str,args))
        cmd = "{} -datadir={} {} {}".format(self.CLIBIN, self.datadir, command, cliargs)
        results = subprocess.check_output(cmd,shell=True).decode().strip()
        try:
            results = json.loads(results)
        except ValueError:
            pass
        return results

    def create_utx(self, funding_tx, amount, vout, receiving_addr):
        input_arg = self._quote(json.dumps([{'txid':funding_tx['txid'],'vout':vout}]))
        output_arg = self._quote(json.dumps({receiving_addr:amount}))
        utx = self('createrawtransaction', input_arg, output_arg)
        return utx

    def sign_tx(self, tx, funding_tx, vout, amount, redeem_script, signing_pk):
        tx = self._quote(tx)
        input_arg = self._quote(json.dumps([{
                                 'txid':funding_tx['txid'],
                                 'vout':vout,
                                 'amount':amount,
                                 'scriptPubKey':funding_tx['vout'][vout]['scriptPubKey']['hex'],
                                 'redeemScript':redeem_script}]))
        pk_arg = self._quote(json.dumps([signing_pk]))
        stx = self('signrawtransaction', tx, input_arg, pk_arg)
        return stx

    def import_wif_pk(self, wif_pk, rescan='false'):
        self("importprivkey", wif_pk, self.account, rescan)
    
    def get_addr_priv_key_pairs(self):
        addresses = self("getaddressesbyaccount", self.account)
    
        pairs={}
        for addr in addresses:
            priv_key = self("dumpprivkey", addr)
            pairs[addr] = priv_key 
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
        hex_pk = self._create_hex_pk(*hex_seeds)
        wif_pk = self._hex_to_wif_pk(hex_pk)
        self.import_wif_pk(wif_pk)

    def seed_addresses(self, *hex_seeds):
        for seed in hex_seeds:
            assert len(seed) % 2 == 0
            urand = binascii.hexlify(os.urandom(int(len(seed)/2))).decode()
            self.create_address(seed,urand)

    def _create_hex_pk(self, *hex_seeds):
        hashes = [int(hashlib.sha256(seed.encode()).hexdigest(),16) for seed in hex_seeds] 
        xor = reduce(lambda x,y: x ^ y, hashes)
        hexed = "{:x}".format(xor)
        if len(hexed) % 2:
            hexed = hexed[:-1]
        return hexed

    def _checksum(self, prefixed_key):
## unhex and hash twice
        unhexed = binascii.unhexlify(prefixed_key)
        hashed = hashlib.sha256(hashlib.sha256(unhexed).digest()).hexdigest()
        checksum = hashed[:8]
        return checksum
    
    def _hex_to_wif_pk(self, hex_pk):
## prefix 0x80 byte
        prefixed_key = self.WIFPREFIX + hex_pk
## unhex and hash twice
        unhexed = binascii.unhexlify(prefixed_key)
        hashed = hashlib.sha256(hashlib.sha256(unhexed).digest()).hexdigest()
## append checksum 
        checksummed_key = prefixed_key + hashed[0:8]
## unhex again and encode binary data ?
        wif = base58.encode(binascii.unhexlify(checksummed_key))
        
        return wif

    def _wif_to_hex_pk(self, wif_pk):
        checksummed_pk = binascii.hexlify(base58.decode(wif_pk)).decode()
## drop prefix byte and appended 4-byte checksum
        hex_pk = checksummed_pk[2:-8]
        
        return hex_pk
    
    def _quote(self, cliarg):
        return "'{}'".format(cliarg)

    def _require_tmpfs(self):
        df_out = subprocess.check_output("df -T {} ".format(self.datadir),shell=True).decode().strip().splitlines()
## headers and one row
        assert len(df_out) == 2
## filesystem type is second column
        fs_type = df_out[-1].split()[1].strip()
        assert fs_type == 'tmpfs'

class NamecoinCli(BitcoinCli):
    CLIBIN = 'namecoin-cli'
    WIFPREFIX = 'B4'

class BitcoinCashCli(BitcoinCli):
    pass
