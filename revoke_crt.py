#!/usr/bin/env python3
import argparse, subprocess, json, os, urllib.request, sys, base64, binascii, copy, \
    tempfile, re

from urllib.request import urlopen
from urllib.error import HTTPError

def revoke_crt(account_key, crt):
    """Use the ACME protocol to revoke an ssl certificate signed by a
    certificate authority.

    :param string account_key: Path to your Let's Encrypt account private key.
    :param string crt: Path to the signed certificate.
    """
    #CA = "https://acme-staging-v02.api.letsencrypt.org"
    CA = "https://acme-v02.api.letsencrypt.org"
    DIRECTORY = json.loads(urlopen(CA + "/directory").read().decode('utf8'))

    def _b64(b):
        "Shortcut function to go from bytes to jwt base64 string"
        if type(b) is str:
            b = b.encode()

        return base64.urlsafe_b64encode(b).decode().replace("=", "")

    def _a64(a):
        "Shortcut function to go from jwt base64 string to bytes"
        return base64.urlsafe_b64decode(str(a + ("=" * (len(a) % 4))))

    # helper function - run external commands
    def _cmd(cmd_list, stdin=None, cmd_input=None, err_msg="Command Line Error"):
        proc = subprocess.Popen(cmd_list, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(cmd_input)
        if proc.returncode != 0:
            raise IOError("{0}\n{1}".format(err_msg, err))
        return out

    # helper function - make request and automatically parse json response
    def _do_request(url, data=None, err_msg="Error", depth=0):
        try:
            resp = urllib.request.urlopen(urllib.request.Request(url, data=data, headers={"Content-Type": "application/jose+json", "User-Agent": "acme-nosudo"}))
            resp_data, code, headers = resp.read().decode("utf8"), resp.getcode(), resp.headers
        except IOError as e:
            resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
            code, headers = getattr(e, "code", None), {}
        try:
            resp_data = json.loads(resp_data) # try to parse json results
        except ValueError:
            pass # ignore json parsing errors
        if depth < 100 and code == 400 and resp_data['type'] == "urn:ietf:params:acme:error:badNonce":
            raise IndexError(resp_data) # allow 100 retrys for bad nonces
        if code not in [200, 201, 204]:
            raise ValueError("{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(err_msg, url, data, code, resp_data))
        return resp_data, code, headers

    # helper function - make signed requests
    def _send_signed_request(url, payload, err_msg, depth=0):
        payload64 = "" if payload is None else _b64(json.dumps(payload).encode('utf8'))
        new_nonce = _do_request(DIRECTORY['newNonce'])[2]['Replay-Nonce']
        protected = {"url": url, "alg": "RS256", "nonce": new_nonce}
        protected.update({"jwk": jwk} if acct_headers is None else {"kid": acct_headers['Location']})
        protected64 = _b64(json.dumps(protected).encode('utf8'))
        protected_input = "{0}.{1}".format(protected64, payload64).encode('utf8')
        out = _cmd(["openssl", "dgst", "-sha256", "-sign", account_key], stdin=subprocess.PIPE, cmd_input=protected_input, err_msg="OpenSSL Error")
        data = json.dumps({"protected": protected64, "payload": payload64, "signature": _b64(out)})
        try:
            return _do_request(url, data=data.encode('utf8'), err_msg=err_msg, depth=depth)
        except IndexError: # retry bad nonces (they raise IndexError)
            return _send_signed_request(url, payload, err_msg, depth=(depth + 1))

    # Step 1: Get account public key
    sys.stderr.write("Reading pubkey file...\n")
    out = _cmd(["openssl", "rsa", "-in", account_key, "-noout", "-text"], err_msg="Error reading account public key")

    pub_hex, pub_exp = re.search(
        r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        out.decode('utf8'), re.MULTILINE|re.DOTALL).groups()
    pub_mod = binascii.unhexlify(re.sub("(\s|:)", "", pub_hex))
    pub_mod64 = _b64(pub_mod)
    pub_exp = int(pub_exp)
    pub_exp = "{0:x}".format(pub_exp)
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    pub_exp = binascii.unhexlify(pub_exp)
    pub_exp64 = _b64(pub_exp)
    jwk = {
        "e": pub_exp64,
        "kty": "RSA",
        "n": pub_mod64,
    }
    sys.stderr.write("Found public key!\n")

    # Step 2: Get account info.
    sys.stderr.write("Getting account info...\n")
    reg = {
        "onlyReturnExistiing": True
    }
    acct_headers = None
    result, code, acct_headers = _send_signed_request(DIRECTORY['newAccount'], reg, "Error getting account info")

    # Step 3: Generate the payload.
    crt_der = _cmd(["openssl", "x509", "-in", crt, "-outform", "DER"], err_msg="DER export error")
    crt_der64 = _b64(crt_der)
    rvk_payload = {
        "certificate": crt_der64,
    }
    _send_signed_request(DIRECTORY['revokeCert'], rvk_payload, "Error revoking certificate")
    sys.stderr.write("Certificate revoked!\n")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""\
Get a SSL certificate revoked by a Let's Encrypt (ACME) certificate
authority.  You do NOT need to run this script on your server, it is
meant to be run on your computer.

NOTE: YOUR USER KEY NEEDS TO BE THE SAME KEY USED TO ISSUE THE CERTIFICATE.

Prerequisites:
* openssl
* python 3

Example:
--------------
$ python3 revoke_crt.py --account-key user.key domain.crt
--------------

""")
    parser.add_argument("-k", "--account-key", required=True, help="path to your Let's Encrypt account private key")
    parser.add_argument("crt_path", help="path to your signed certificate")

    args = parser.parse_args()
    revoke_crt(args.account_key, args.crt_path)

