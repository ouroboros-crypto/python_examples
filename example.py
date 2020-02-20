import binascii
import hashlib
from typing import Dict

from secp256k1 import PrivateKey
import bech32
import requests


def generate_wallet() -> Dict[str, str]:
    '''Generates a new wallet and returns its data'''
    privkey = PrivateKey().serialize()

    return {
        "private_key": privkey,
        "public_key": privkey_to_pubkey(privkey),
        "address": privkey_to_address(privkey),
    }


def privkey_to_pubkey(privkey: str) -> str:
    '''converts privkey to pubkey'''
    privkey_obj = PrivateKey(binascii.unhexlify(privkey))

    return privkey_obj.pubkey.serialize().hex()


def pubkey_to_address(pubkey: str) -> str:
    '''converts pubkey to address'''
    pubkey_bytes = binascii.unhexlify(pubkey)

    s = hashlib.new("sha256", pubkey_bytes).digest()
    r = hashlib.new("ripemd160", s).digest()

    return bech32.bech32_encode("ouro", bech32.convertbits(r, 8, 5))


def privkey_to_address(privkey: str) -> str:
    '''converts privkey to address'''
    pubkey = privkey_to_pubkey(privkey)

    return pubkey_to_address(pubkey)


def get_account_data(address) -> Dict:
    r = requests.get('https://rest.ouroboros-crypto.com/auth/accounts/{}'.format(address))

    return r.json()


def example():
    wallet = generate_wallet()

    print('Generated wallet: {}'.format(wallet))

    print('Private Key: {}'.format(wallet['private_key']))
    print('Public Key: {}'.format(privkey_to_pubkey(wallet['private_key'])))
    print('Address: {}'.format(privkey_to_address(wallet['private_key'])))

    print('Account Data: {}'.format(
        get_account_data(privkey_to_address(wallet['private_key']))
    ))


if __name__ == '__main__':
    example()
