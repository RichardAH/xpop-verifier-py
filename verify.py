import sys
import json
import xrpl

def err(e):
    sys.stderr.write("Error: " + e)
    return False

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

    # RH: TODO actual validation here

    try:
        tx = xrpl.core.binarycodec.decode(transaction["blob"])
        meta = xrpl.core.binarycodec.decode(transaction["meta"])
    except:
        return err("Error decoding txblob and meta")

    return (tx, meta)

xpop = ''
for line in sys.stdin:
    xpop += line.rstrip()


print(verify(xpop))
