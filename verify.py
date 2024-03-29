# XRPL Proof of Payment Verifier
# Author: Richard Holland
# Date: 24/7/21
# Verifies a proof of payment payload (Note: XLS pending)
# See: https://github.com/RichardAH/xrpl-proof-of-validation

import sys
import json
import xrpl
import hashlib
from binascii  import hexlify, unhexlify
import math
import base64

def err(e):
    sys.stderr.write("Error: " + e + "\n")
    return False

# This function shouldn't technically be needed but xrpl-py needs updating
# for validation fields. There's only one signing field: sfSignature, we need to 
# clip around it.
# @return {
#   without_signature: input sans signing field, 
#   key: key, signature: signature, ledger_hash: ledgerhash }
def process_validation_message(val):
    if type(val) == str:
        val = unhexlify(val)
    
    upto = 0
    rem = len(val)

    ret = {}

    sig_start = 0
    sig_end = 0
    
    # Flags
    if val[upto] != 0x22 or rem < 5:
        return err("validation: sfFlags missing")
    upto += 5; rem -= 5;

    # LedgerSequence
    if val[upto] != 0x26 or rem < 5:
        return err("validation: sfLedgerSequence missing")
    upto += 5; rem -= 5;

    # CloseTime (optional)
    if val[upto] == 0x27:
        if rem < 5:
            return err("validation: sfCloseTime missing payload")
        upto += 5; rem -= 5

    # SigningTime
    if val[upto] != 0x29 or rem < 5:
        return err("validation: sfSigningTime missing")
    upto += 5; rem -= 5;

    # LoadFee (optional)
    if val[upto] == 0x20 and rem >= 2 and val[upto+1] == 0x18:
        if rem < 6:
            return err("validation: sfLoadFee missing payload")
        upto += 6; rem -= 6
        
    # ReserveBase (optional)
    if val[upto] == 0x20 and rem >= 2 and val[upto+1] == 0x1F:
        if rem < 6:
            return err("validation: sfReserveBase missing payload")
        upto += 6; rem -= 6

    # ReserveIncrement (optional)
    if val[upto] == 0x20 and rem >= 2 and val[upto+1] == 0x20:
        if rem < 6:
            return err("validation: sfReserveIncrement missing payload")
        upto += 6; rem -= 6
    
    # BaseFee (optional)
    if val[upto] == 0x35:
        if rem < 9:
            return err("validation: sfBaseFee missing payload")
        upto += 9; rem -= 9

    # Cookie (optional)
    if val[upto] == 0x3A:
        if rem < 9:
            return err("validation: sfCookie missing payload")
        upto += 9; rem -= 9
   
    # ServerVersion (optional)
    if val[upto] == 0x3B:
        if rem < 9:
            return err("validation: sfServerVersion missing payload")
        upto += 9; rem -= 9

    # LedgerHash
    if val[upto] != 0x51 or rem < 33:
        return err("validation: sfLedgerHash missing")
    
    ret["ledger_hash"] = str(hexlify(val[upto+1:upto+33]), 'utf-8').upper()
    upto += 33; rem -= 32

    # ConsensusHash (optional)
    if val[upto] == 0x50 and rem >= 2 and val[upto+1] == 0x17:
        if rem < 34:
            return err("validation: sfConsensusHash payload missing")
        upto += 34; rem -= 34

    # ValidatedHash (optioonal)
    if val[upto] == 0x50 and rem >= 2 and val[upto+1] == 0x19:
        if rem < 34:
            return err("validation: sfValidatedHash payload missing")
        upto += 34; rem -= 34

    # SigningPubKey
    if val[upto] != 0x73 or rem < 3:
        return err("validation: sfSigningPubKey missing")

    keysize = val[upto+1]
    upto += 2; rem -= 2
    if keysize > rem:
        return err("validation: sfSigningPubKey incomplete")

    ret["key"] = str(hexlify(val[upto:upto+keysize]), 'utf-8').upper()

    upto += keysize; rem -= keysize

    # Signature
    sigstart = upto
    if val[upto] != 0x76 or rem < 3:
        return err("validation: sfSignature missing")
    
    sigsize = val[upto+1] 
    upto += 2; rem -= 2
    if sigsize > rem:
        return err("validation: sfSignature incomplete")
    
    ret["signature"] = val[upto:upto+sigsize]

    upto += sigsize; rem -= sigsize

    ret["without_signature"] = val[:sigstart] + val[upto:]

    return ret

# Create a variable length prefix for a xrpl serialized vl field
def make_vl_bytes(l):
    if type(l) == float:
        l = ceil(l)
    if type(l) != int:
        return False
    if l <= 192:
        return bytes([l])
    elif l <= 12480:
        b1 = math.floor((l - 193) / 256 + 193)
        return bytes([b1, l - 193 - 256 * (b1 - 193)])
    elif l <= 918744:
        b1 = math.floor((l - 12481) / 65536 + 241)
        b2 = math.floor((l - 12481 - 65536 * (b1 - 241)) / 256)
        return bytes([b1, b2, l - 12481 - 65536 * (b1 - 241) - 256 * b2])
    else:
        return err("Cannot generate vl for length = " + str(l) + ", too large")

def sha512(x):
    m = hashlib.sha512()
    m.update(x)
    return m.digest()

def sha512h(x):
    m = hashlib.sha512()
    m.update(x)
    return m.digest()[:32]

def hash_txn(txn):
    if type(txn) == str:
        txn = unhexlify(txn)
    return sha512h(b'TXN\x00' + txn)

# Hash the txn and meta data as a leaf node in the shamap
def hash_txn_and_meta(txn, meta):
    if type(txn) == str:
        txn = unhexlify(txn)

    if type(meta) == str:
        meta = unhexlify(meta)

    vl1 = make_vl_bytes(len(txn))
    vl2 = make_vl_bytes(len(meta))
    
    if vl1 == False or vl2 == False:
        return False

    payload = b'SND\x00' + vl1 + txn + vl2 + meta + hash_txn(txn)
    #print("payload1", hexlify(payload))
    return sha512h(payload)


def hash_ledger(idx, coins, phash, txroot, acroot, pclose, close, res, flags):
    if type(idx) == str:
        idx = int(idx)
    if type(coins) == str:
        coins = int(coins)
    if type(phash) == str:
        phash = unhexlify(phash)
    if type(txroot) == str:
        txroot = unhexlify(txroot)
    if type(acroot) == str:
        acroot = unhexlify(acroot)
    if type(pclose) == str:
        pclose = int(pclose)
    if type(close) == str:
        close = int(close)
    if type(res) == str:
        res = int(res)
    if type(flags) == str:
        flags = int(flags)

    if type(idx) != int or type(coins) != int or type(pclose) != int \
    or type(close) != int or type(res) != int or type(flags) != int:
        return err("Invalid int arguments to hash_ledger")

    idx = int.to_bytes(idx, byteorder='big', length=4)
    coins = int.to_bytes(coins, byteorder='big', length=8)
    pclose = int.to_bytes(pclose, byteorder='big', length=4)
    close = int.to_bytes(close, byteorder='big', length=4)
    res = int.to_bytes(res, byteorder='big', length=1)
    flags = int.to_bytes(flags, byteorder='big', length=1)

    if type(phash) != bytes or type(txroot) != bytes or type(acroot) != bytes:
        return err("Invalid bytes arguments to hash_ledger")

    payload = b'LWR\x00' + idx + coins + phash + txroot + acroot + pclose + close + res + flags
    return sha512h(payload)

def hash_proof(proof, depth=0):
    if type(proof) != list and type(proof) != dict:
        return err('Proof must be a list or dict')
    
    if type(proof) == list and len(proof) < 16:
        return False

    hasher = hashlib.sha512()
    hasher.update(b'MIN\x00')

    if type(proof) == list:
        for i in range(16):
            if type(proof[i]) == str:
                hasher.update(unhexlify(proof[i]))
            elif type(proof[i]) == list:
                hasher.update(hash_proof(proof[i], depth+1))
            else:
                return err("Unknown object in proof list")
    else:
        if 'children' in proof and len(proof['children']) > 0:
            for x in range(16):
                i = "0123456789ABCDEF"[x]
                if not i in proof['children']:
                    hasher.update(bytes(32))
                    continue
                h = hash_proof(proof['children'][i], depth+1)
                hasher.update(h)
        elif 'hash' in proof:
            return unhexlify(proof['hash'])
        else:
            return err("Missing hash key in proof leaf")

    return hasher.digest()[:32]
    

def proof_contains(proof, h):
    if type(proof) != list and type(proof) != dict:
        return False

    if "children" in proof:
        return proof_contains(proof["children"], h)

    if type(h) == str:
        h = unhexlify(h)

    for x in range(16):
        i = x
        if type(proof) == dict:
            i = "0123456789ABCDEF"[x]

        if not i in proof:
            continue
        if type(proof[i]) == str and unhexlify(proof[i]) == h or \
               'hash' in proof[i] and unhexlify(proof[i]['hash']) == h or \
                proof_contains(proof[i], h):
            return True

    return False

def verify(xpop, vl_key):
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

    if not "unl" in validation:
        return err("XPOP did not contain valdation.unl")

    if not "data" in validation:
        return err("XPOP did not contain validation.data")

    unl = validation["unl"]
    data = validation["data"]

    if not "public_key" in unl:
        return err("XPOP did not contain validation.unl.public_key")

    if type(vl_key) == bytes:
        vl_key = hexlify(vl_key).upper()


    ##
    ## Part A: Validate and decode UNL
    ##

    # 1. If the vl key is wrong then everything is wrong.
    if vl_key.lower() != unl["public_key"].lower():
        return err("XPOP vl key is not one we recognise")

    # 2. Grab the manifest and signature as bytes objects
    if not "manifest" in unl:
        return err("XPOP did not contain validation.unl.manifest")
    if not "signature" in unl:
        return err("XPOP did not contain validation.unl.signature")
    manifest = None
    signature = None
    try:
        manifest = xrpl.core.binarycodec.decode(\
                str(hexlify(base64.b64decode(unl["manifest"])), "utf-8"))
        signature = unhexlify(unl["signature"])
    except:
        return err("XPOP invalid validation.unl.manifest (should be base64) or validation.unl.signature")

    if not "MasterSignature" in manifest or not "Signature" in manifest:
        return err("XPOP invalid validation.unl.manifest serialization")

    # 3. Re-encode the manifest without signing fields so we can check the signature
    manifestnosign = b'MAN\x00' + \
            unhexlify(xrpl.core.binarycodec.encode_for_signing(manifest)[8:])

    # 4. Check master signature (vl_key over vl manifest)
    if not xrpl.core.keypairs.is_valid_message(\
        manifestnosign,\
        unhexlify(manifest["MasterSignature"]), manifest["PublicKey"]):
        return err("XPOP vl signature validation failed")

    # 5. Get UNL signing key
    signing_key = manifest["SigningPubKey"]

    # 6. Get raw UNL payload
    payload = None
    if not "blob" in unl:
        return err("XPOP invalid validation.unl.blob")
    
    payload = base64.b64decode(unl["blob"])

    # 7. Check UNL blob signature
    if not xrpl.core.keypairs.is_valid_message(\
        payload,\
        unhexlify(unl["signature"]),
        signing_key):
        return err("XPOP invalid validation.unl.blob signature")

    # 8. Decode UNL blob
    try:
        payload = json.loads(payload)
    except:
        return err("XPOP invalid validation.unl.blob json")

    if not "sequence" in payload:
        return err("XPOP missing validation.unl.blob.sequence")

    if not "expiration" in payload:
        return err("XPOP missing validation.unl.blob.expiration")

    if not "validators" in payload:
        return err("XPOP missing validation.unl.blob.validators")

    unlseq = payload["sequence"]        # these are not validated but are returned
    unlexp = payload["expiration"]      # to the user(dev) for additional validation
    validators = {}

    validators_master_key = {} # map of master key to signing key

    # 9. Check UNL internal manifests and get validator signing keys
    for v in payload["validators"]:
        if not "validation_public_key" in v:
            return err("XPOP missing validation_public_key from unl entry")
        if not "manifest" in v:
            return err("XPOP missing manifest from unl entry")
    
        manifest = None
        try:
            manifest = base64.b64decode(v["manifest"])
            manifest = str(hexlify(manifest), "utf-8")
            manifest = xrpl.core.binarycodec.decode(manifest)
        except:
            return err("XPOP invalid manifest in unl entry")
        
        if not "MasterSignature" in manifest:
            return err("XPOP manifest missing master signature in unl entry")

        if not "SigningPubKey" in manifest:
            return err("XPOP manifest missing signing key in unl entry")

        # 10. Check each validator's manifest is signed correctly
        #manifestnosign = b'MAN\x00' + \
        #    unhexlify(xrpl.core.binarycodec.encode_for_signing(manifest)[8:])

        # RH NOTE: this doesn't provide any real additional safety since the whole blob is already signed
        # and verifying these uses a lot of cpu cycles... so it's left commented oout
        #if not xrpl.core.keypairs.is_valid_message(\
        #    manifestnosign,
        #    unhexlify(manifest["MasterSignature"]),
        #    v["validation_public_key"]):
        #    return err("XPOP a unl entry was invalidly signed")

        # 11. Compute the node public address from the signing key
        nodepub = xrpl.core.addresscodec.encode_node_public_key(\
            unhexlify(manifest["SigningPubKey"]))
        nodemaster = xrpl.core.addresscodec.encode_node_public_key(\
            unhexlify(manifest["PublicKey"]))

        # 12. Add the verified validator to the verified validator list
        validators[nodepub] = manifest["SigningPubKey"]
        validators_master_key[nodemaster] = nodepub

    ##
    ## Part B: Validate TXN and META proof, and compute ledger hash
    ##

    # 13. Check if the transaction and meta is actually in the proof
    computed_tx_hash_and_meta = hash_txn_and_meta(transaction["blob"], transaction["meta"])

    if not proof_contains(transaction["proof"], computed_tx_hash_and_meta):
        return err("Txn and meta were not present in provided proof")

    # 14. Compute the tx merkle root
    computed_tx_root = hash_proof(transaction["proof"])

    # 15. Compute the ledger hash from the tx merkle root
    computed_ledger_hash = \
        hash_ledger(ledger["index"], ledger["coins"], ledger["phash"], computed_tx_root, \
            ledger["acroot"], ledger["pclose"], ledger["close"], ledger["cres"], ledger["flags"])


    if computed_ledger_hash == False:
        return False

    computed_ledger_hash = str(hexlify(computed_ledger_hash), 'utf-8').upper()

    ##
    ## Part C: Check validations to see if a quorum was reached on the computed ledgerhash
    ##

    # 16. Calculate the minimum number of UNL validation signatures we need
    quorum = math.ceil(len(validators) * 0.8)
    votes = 0

    # 17. Step through the provided validation messages and check each one's signature and ledger hash
    used_key = {}

    for nodepub in data:

        datakey = nodepub

        if nodepub in validators_master_key and validators_master_key[nodepub] in validators:
            used_key[nodepub] = True
            nodepub = validators_master_key[nodepub]

        # RH NOTE: Any validation messages not the UNL are skipped, although this should probably be an error
        if not nodepub in validators:
            print("nodepub not in validators: ", nodepub)
            continue
        
        if nodepub in used_key:
            continue

        used_key[nodepub] = True


        # 18. Parse the validation message
        valmsg = process_validation_message(data[datakey])
        if valmsg == False:
            err("Warning: XPOP contained invalid validation from " + nodepub)
            continue

        # 19. Check the signing key matches the key we have on file from the (now verified) UNL
        if valmsg["key"] != validators[nodepub]:
            err("Warning: XPOP contained invalid KEY for validation from " + nodepub)
            continue
        
        # 20. Check the ledger hash in the validation message matches the one we generated from tx merkel
        if valmsg["ledger_hash"] != computed_ledger_hash:
            #err("Warning: XPOP contained validation for another ledger hash")
            continue
        
        # 21. Check the signature on the validation message (expensive)
        valpayload = b'VAL\x00' + valmsg["without_signature"]
        if not xrpl.core.keypairs.is_valid_message(valpayload, valmsg["signature"], valmsg["key"]):
            err("Warning: XPOP contained validation with invalid signature")
            continue

        # 22. If all is well the successfully verified validation message counts as a vote toward quorum
        votes += 1
    

    ##
    ## Part D: Return useful information to the caller
    ##

    # 23. If there were insufficiently many votes in favour of the txn we always return False
    if votes < quorum:
        return False

    try:
        tx = xrpl.core.binarycodec.decode(transaction["blob"])
        meta = xrpl.core.binarycodec.decode(transaction["meta"])
    except:
        return err("Error decoding txblob and meta")


    ret = {
        "verified": True,
        "tx_blob": tx,
        "tx_meta": meta,
        "ledger_hash": computed_ledger_hash,
        "ledger_index": ledger["index"],
        "ledger_unixtime": xrpl.utils.ripple_time_to_posix(ledger["close"]),
        "validator_quorum": quorum,
        "validator_count": len(validators),
        "validator_votes": votes,
        "vl_master_key": vl_key,
        "vl_expiration_unixtime": xrpl.utils.ripple_time_to_posix(unlexp),
        "vl_sequence": unlseq,
        "tx_source": tx["Account"],
    }

    if "InvoiceID" in tx:
        ret["tx_invoice_id"] = tx["InvoiceID"]

    ret["tx_is_payment"] = tx["TransactionType"] == "Payment"

    if "DestinationTag" in tx:
        ret["tx_destination_tag"] = tx["DestinationTag"]

    if "Destination" in tx:
        ret["tx_destination"] = tx["Destination"]
        # 24. Search the meta for the modified nodes and construct a delivered amount field for xrp payments
        if "AffectedNodes" in meta:
            for af in meta["AffectedNodes"]:
                if "ModifiedNode" in af:
                    mn = af["ModifiedNode"]
                    if "FinalFields" in mn and "PreviousFields" in mn and \
                    mn["LedgerEntryType"] == "AccountRoot" and "Account" in mn["FinalFields"] and \
                    mn["FinalFields"]["Account"] == tx["Destination"] and \
                    "Balance" in mn["PreviousFields"] and "Balance" in mn["FinalFields"]:
                        ret["tx_delivered_drops"] = \
                                int(mn["FinalFields"]["Balance"]) - int(mn["PreviousFields"]["Balance"])
                        break

    return ret


# Below is just an example on how to use this. It reads an xpop from stdin and run the verifier against
# the XRPLF's validation list key (at time of writing)

xpop = ''
for line in sys.stdin:
    xpop += line.rstrip()

verification_result = verify(xpop, "ED264807102805220DA0F312E71FC2C69E1552C9C5790F6C25E3729DEB573D5860")
        #"ED45D1840EE724BE327ABE9146503D5848EFD5F38B6D5FEDE71E80ACCE5E6E738B")

if verification_result == False:
    print(json.dumps({"verified": False, "info": "Verification failed (tampering or damaged/incomplete/invalid data)"}))
else:
    print(json.dumps(verification_result))
