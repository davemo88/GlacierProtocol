

import subprocess

class CoinCli:
    clibin = "coin-cli"
    
    def __init__(self, datadir="~/.bitcoin/"):
        self.datadir = datadir

    def cmd(self):
        return "{} -datadir={} {}".format(self.clibin, self.datadir)



        

class BtcCli:
    clibin = "bitcoin-cli"

class NmcCli:
    clibin = "namecoin-cli"

class BchCli:
    clibin = "bitcoin-cash-cli"
