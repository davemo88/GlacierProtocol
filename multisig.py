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

    def create_tx(self, input_txs, vouts, address_amounts):
        inputs = self._tx_inputs(inputs_txs, vouts)
        outputs = self._tx_outputs(address_amounts)
        return self("createrawtransaction", inputs, outputs)

    def sign_tx(self, tx, input_txs, vouts, signing_pks, redeem_scripts):
# does this need to be quoted?
        tx = self._quote(tx)
        inputs = self._signing_inputs(input_txs, vouts, redeem_scripts)
        pks = self._quote(json.dumps(signing_pks))
        return self("signrawtransaction", tx, inputs, pks)

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

    def _tx_inputs(self, inputs_txs, vouts):
        tx_inputs = [
            {'txid':itx['txid'], 'vout': vout for vout in vouts[itx['txid']] for itx in input_txs} 
                ]

        return self._quote(json.dumps(tx_inputs))

    def _tx_outputs(self, address_amounts):
        return self._quote(json.dumps({address:amount for address,amount in address_amounts}))

    def _signing_inputs(self, input_txs, vouts, redeem_scripts):
        signing_inputs = []
        for itx in input_txs:
            for vout in vouts[itx['txid']]:
                _input = {
                    'txid': itx['txid'],
                    'vout': vout,
                    'scriptPubKey': itx['vout'][vout]['scriptPubKey']['hex']
                    'amount': itx['vout'][vout]['value']
                        }
                if itx['vout'][vout]['scriptPubKey']['type'] == 'scripthash':
                    try:
                        _input['redeemScript'] = redeem_scripts[itx['txid']][vout]
                    except ValueError:
                        raise ValueError("input tx {} vout {} is scripthash but no redeem script provided".format(itx['txid'], vout))

                signing_inputs.append(_input)

        return self._quote(json.dumps(signing_inputs))

    def _implicit_fee(self, tx):
        pass

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
