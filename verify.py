import sys
import json
import xrpl
import hashlib
from binascii  import hexlify, unhexlify
import math

#const prefix_LWR = '4C575200'
#const prefix_SND = '534E4400'
#const prefix_MIN = '4D494E00'
#const prefix_TXN = '54584E00'

def err(e):
    sys.stderr.write("Error: " + e)
    return False

def make_vl_bytes(l):
    if type(l) == float:
        l = ceil(l)
    if type(l) != int:
        return False
    if l <= 192:
        return bytes([l])
    elif l <= 12480:
        b1 = floor((l - 193) / 256 + 193)
        return bytes([b1, l - 193 - 256 * (b1 - 193)])
    elif l <= 918744:
        b1 = floor((l - 12481) / 65536 + 241)
        b2 = floor((l - 12481 - 65536 * (b1 - 241)) / 256)
        return bytes([b1, b2, l - 12481 - 65536 * (b1 - 241) - 256 * b2])
    else:
        return err("Cannot generate vl for length = " + str(l) + ", too large")

def sha512h(x):
    m = hashlib.sha512()
    m.update(x)
    return m.digest()[:32]

def hash_txn(txn):
    if type(txn) == str:
        txn = unhexlify(txn)
    return sha512h(b'TXN\x00' + txn)

def hash_txn_and_meta(txn, meta):
    if type(txn) == str:
        txn = unhexlify(txn)

    if type(meta) == str:
        meta = unhexlify(meta)

    vl1 = make_vl_bytes(len(txn))
    vl2 = make_vl_bytes(len(meta))
    
    if vl1 == False or vl2 == False:
        return False

    return sha512h(b'SND\x00' + vl1 + txn + vl2 + meta + hash_txn(txn))


def hash_proof(proof):
    if type(proof) != list:
        return err('Proof must be a list')
    
    if len(proof) < 16:
        return False

    hasher = hashlib.sha512()
    hasher.update(b'MIN\x00')

    for i in range(16):
        if type(proof[i]) == str:
            hasher.update(unhexlify(proof[i]))
        elif type(proof[i]) == list:
            hasher.update(hash_proof(proof[i]))
        else:
            return err("Unknown object in proof list")

    return hasher.digest()[:32]
    

def verify(xpop):
    if type(xpop) == str:
        try:
            xpop = json.loads(xpop)
        except:
            return err("Invalid json")

    if type(xpop) != dict:
        return err("Expecting either a string or a dict")

    if not "ledger" in xpop:
        return err("XPOP did not contain ledger")

    if not "validation" in xpop:
        return err("XPOP did not contain validation")

    if not "transaction" in xpop:
        return err("XPOP did not contain transaction")

    ledger = xpop["ledger"]
    validation = xpop["validation"]
    transaction = xpop["transaction"]

    print("ledger")
    print(ledger)

    print("proof")
    print(hexlify(hash_proof(transaction["proof"])))

    # RH: TODO actual validation here

    try:
        tx = xrpl.core.binarycodec.decode(transaction["blob"])
        meta = xrpl.core.binarycodec.decode(transaction["meta"])
    except:
        return err("Error decoding txblob and meta")

    return hash_txn(transaction["blob"])
    #return (tx, meta)

#print(sha512h(b''))

xpop = ''
for line in sys.stdin:
    xpop += line.rstrip()

#print(
verify(xpop)
