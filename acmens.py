# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: AGPL-3.0-only
#
# Copyright © 2015-2018 Daniel Roesler <diafygi@gmail.com>
# Copyright © 2021-2022 siddharth ravikumar <s@ricketyspace.net>
#

import argparse
import subprocess
import json
import urllib.request
import sys
import base64
import binascii
import time
import hashlib
import re

from urllib.request import urlopen
from urllib.error import URLError


__version__ = "0.3.0"

CA_PRD = "https://acme-v02.api.letsencrypt.org"
CA_STG = "https://acme-staging-v02.api.letsencrypt.org"
CA_DIR = None


def _directory(ca_url):
    global CA_DIR
    if CA_DIR is None:
        CA_DIR = json.loads(urlopen(ca_url + "/directory").read().decode("utf8"))
    return CA_DIR


def _b64(b):
    "Convert bytes to JWT base64 string"
    if type(b) is str:
        b = b.encode()
    return base64.urlsafe_b64encode(b).decode().replace("=", "")


def _cmd(cmd_list, stdin=None, cmd_input=None, err_msg="Command Line Error"):
    "Runs external commands"
    proc = subprocess.Popen(
        cmd_list, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, err = proc.communicate(cmd_input)
    if proc.returncode != 0:
        sys.stderr.write("{0}: {1}\n".format(err_msg, err.decode()))
        sys.exit(1)
    return out


def _do_request(url, data=None, err_msg="Error"):
    try:
        resp = urllib.request.urlopen(
            urllib.request.Request(
                url,
                data=data,
                headers={
                    "Content-Type": "application/jose+json",
                    "User-Agent": "acmens",
                },
            )
        )
        resp_data, code, headers = (
            resp.read().decode("utf8"),
            resp.getcode(),
            resp.headers,
        )
    except URLError as e:
        resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
        code, headers = getattr(e, "code", None), {}
    try:
        resp_data = json.loads(resp_data)  # try to parse json results
    except ValueError:
        pass  # resp_data is not a JSON string; that's fine
    return resp_data, code, headers


def _mk_signed_req_body(url, payload, nonce, auth, account_key):
    if len(nonce) < 1:
        sys.stderr.write("_mk_signed_req_body: nonce invalid: {}".format(nonce))
        sys.exit(1)

    payload64 = "" if payload is None else _b64(json.dumps(payload).encode("utf8"))
    protected = {"url": url, "alg": "RS256", "nonce": nonce}
    protected.update(auth)
    protected64 = _b64(json.dumps(protected).encode("utf8"))
    protected_input = "{0}.{1}".format(protected64, payload64).encode("utf8")
    out = _cmd(
        ["openssl", "dgst", "-sha256", "-sign", account_key],
        stdin=subprocess.PIPE,
        cmd_input=protected_input,
        err_msg="OpenSSL Error",
    )
    return json.dumps(
        {"protected": protected64, "payload": payload64, "signature": _b64(out)}
    )


def _send_signed_request(url, payload, nonce_url, auth, account_key, err_msg):
    """Make signed request to ACME endpoint"""
    tried = 0
    nonce = _do_request(nonce_url)[2]["Replay-Nonce"]
    while True:
        data = _mk_signed_req_body(url, payload, nonce, auth, account_key)
        resp_data, resp_code, headers = _do_request(
            url, data=data.encode("utf8"), err_msg=err_msg
        )
        if resp_code in [200, 201, 204]:
            return resp_data, resp_code, headers
        elif (
            resp_code == 400
            and resp_data.get("type", "") == "urn:ietf:params:acme:error:badNonce"
            and tried < 100
        ):
            nonce = headers.get("Replay-Nonce", "")
            tried += 1
            continue
        else:
            sys.stderr.write(
                "{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(
                    err_msg, url, data, resp_code, resp_data
                )
            )
            sys.exit(1)


def _poll_until_not(url, pending_statuses, nonce_url, auth, account_key, err_msg):
    """Poll until status is not in pending_statuses"""
    result, t0 = None, time.time()
    while result is None or result["status"] in pending_statuses:
        assert time.time() - t0 < 3600, "Polling timeout"  # 1 hour timeout
        time.sleep(0 if result is None else 2)
        result, _, _ = _send_signed_request(
            url, None, nonce_url, auth, account_key, err_msg
        )
    return result


def _do_challenge(challenge_type, authz_url, nonce_url, auth, account_key, thumbprint):
    """Do ACME challenge"""
    # Request challenges
    sys.stderr.write("Requesting challenges...\n")
    chl_result, chl_code, chl_headers = _send_signed_request(
        authz_url, None, nonce_url, auth, account_key, "Error getting challenges"
    )
    domain = chl_result["identifier"]["value"]

    # Choose challenge.
    preferred_type = "dns-01" if challenge_type == "dns" else "http-01"
    challenge = None
    dns_challenge = None
    http_challenge = None
    for c in chl_result["challenges"]:
        if c["type"] == preferred_type:
            challenge = c
        if c["type"] == "dns-01":
            dns_challenge = c
        if c["type"] == "http-01":
            http_challenge = c
    if challenge is None:
        if http_challenge:
            # Fallback to http challenge.
            challenge = http_challenge
            challenge_type = "http"
        elif dns_challenge:
            # Fallback to dns challenge.
            challenge = dns_challenge
            challenge_type = "dns"
        else:
            sys.stderr.write("Error: Unable to find challenges!")
            sys.exit(1)
    keyauthorization = "{0}.{1}".format(challenge["token"], thumbprint)
    dns_payload = _b64(hashlib.sha256(keyauthorization.encode()).digest())

    # Ask the user to host the token on their server
    if challenge_type == "dns":
        sys.stderr.write(
            """\
Please update your DNS for '{domain}' to have the following TXT record:

--------------
_acme-challenge    IN    TXT ( \"{keyauth}\" )
--------------

""".format(
                domain=domain, keyauth=dns_payload
            )
        )
        final_msg = "You can remove the _acme-challenge DNS TXT record now."
    else:
        # Challenge response for http server.
        response_uri = ".well-known/acme-challenge/{0}".format(challenge["token"])
        sys.stderr.write(
            """\
Please update your server to serve the following file at this URL:

--------------
URL: http://{domain}/{uri}
File contents: \"{token}\"
--------------

Notes:
- Do not include the quotes in the file.
- The file should be one line without any spaces.

""".format(
                domain=domain, uri=response_uri, token=keyauthorization
            )
        )
        final_msg = "You can remove the acme-challenge file from your webserver now."

    stdout = sys.stdout
    sys.stdout = sys.stderr
    if challenge_type == "dns":
        input("Press Enter when the TXT record is updated on the DNS...")
    else:
        input("Press Enter when you've got the file hosted on your server...")
    sys.stdout = stdout

    # Let the CA know you're ready for the challenge
    sys.stderr.write("Requesting verification for {0}...\n".format(domain))
    _send_signed_request(
        challenge["url"],
        {},
        nonce_url,
        auth,
        account_key,
        "Error requesting challenge verfication: {0}".format(domain),
    )
    chl_verification = _poll_until_not(
        challenge["url"],
        ["pending"],
        nonce_url,
        auth,
        account_key,
        "Error checking challenge verification",
    )
    if chl_verification["status"] != "valid":
        raise ValueError(
            "Challenge did not pass for {0}: {1}".format(domain, chl_verification)
        )
    sys.stderr.write("{} verified!\n".format(domain))
    sys.stderr.write("{}\n".format(final_msg))


def _agree_to(terms):
    """Asks user whether they agree to the Let's Encrypt Subscriber
    Agreement. It will immediately exit if user does not agree."""
    sys.stderr.write(
        "\nDo you agree to the Let's Encrypt Subscriber Agreement\n({})? ".format(terms)
    )
    ans = input()
    if re.search(r"^[Yy]", ans) is None:
        sys.stderr.write("Error: Cannot continue. Exiting.\n")
        sys.exit(1)


def sign_csr(ca_url, account_key, csr, email=None, challenge_type="http"):
    """Use the ACME protocol to get an ssl certificate signed by a
    certificate authority.

    :param string ca_url: Let's Encrypt endpoint.
    :param string account_key: Path to the user account key.
    :param string csr: Path to the certificate signing request.
    :param string email: An optional user account contact email
                         (defaults to webmaster@<shortest_domain>)
    :param string challenge_type: The challenge type to use.
                         (defaults to http)

    :returns: Signed Certificate (PEM format)
    :rtype: string

    """

    # Step 1: Get account public key
    sys.stderr.write("Reading pubkey file...\n")
    out = _cmd(
        ["openssl", "rsa", "-in", account_key, "-noout", "-text"],
        err_msg="Error reading account public key",
    )
    pub_hex, pub_exp = re.search(
        r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        out.decode("utf8"),
        re.MULTILINE | re.DOTALL,
    ).groups()
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
    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(",", ":"))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode()).digest())
    sys.stderr.write("Found public key!\n")

    # Step 2: Get the domain names to be certified
    sys.stderr.write("Reading csr file...\n")
    out = _cmd(
        ["openssl", "req", "-in", csr, "-noout", "-text"],
        err_msg="Error loading {}".format(csr),
    )
    domains = set([])
    cn = None
    common_name = re.search("Subject:.*? CN *= *([^\s,;/]+)", out.decode("utf8"))
    if common_name is not None:
        domains.add(common_name.group(1))
        cn = common_name.group(1)
    subj_alt_names = re.search(
        "X509v3 Subject Alternative Name: \n +([^\n]+)\n",
        out.decode("utf8"),
        re.MULTILINE | re.DOTALL,
    )
    if subj_alt_names is not None:
        for san in subj_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                dm = san[4:]
                if cn is None and dm.find("*") == -1:
                    cn = dm
                domains.add(dm)
    sys.stderr.write("Found domains {}\n".format(", ".join(domains)))

    # Step 3: Ask user for contact email
    if not email:
        default_email = "webmaster@{0}".format(cn)
        stdout = sys.stdout
        sys.stdout = sys.stderr
        input_email = input(
            "STEP 1: What is your contact email? ({0}) ".format(default_email)
        )
        email = input_email if input_email else default_email
        sys.stdout = stdout

    # Step 4: Generate the payload for registering user and initiate registration.
    sys.stderr.write("Registering {0}...\n".format(email))
    _agree_to(_directory(ca_url)["meta"]["termsOfService"])
    reg = {"termsOfServiceAgreed": True}
    nonce_url = _directory(ca_url)["newNonce"]
    auth = {"jwk": jwk}
    acct_headers = None
    result, code, acct_headers = _send_signed_request(
        _directory(ca_url)["newAccount"],
        reg,
        nonce_url,
        auth,
        account_key,
        "Error registering",
    )
    if code == 201:
        sys.stderr.write("Registered!\n")
    else:
        sys.stderr.write("Already registered!\n")
    auth = {"kid": acct_headers["Location"]}

    sys.stderr.write("Updating account...")
    ua_result, ua_code, ua_headers = _send_signed_request(
        acct_headers["Location"],
        {"contact": ["mailto:{}".format(email)]},
        nonce_url,
        auth,
        account_key,
        "Error updating account",
    )
    sys.stderr.write("Done\n")

    # Step 5: Request challenges for domains
    sys.stderr.write("Making new order for {0}...\n".format(", ".join(domains)))
    id = {"identifiers": []}
    for domain in domains:
        id["identifiers"].append({"type": "dns", "value": domain})
    order, order_code, order_headers = _send_signed_request(
        _directory(ca_url)["newOrder"],
        id,
        nonce_url,
        auth,
        account_key,
        "Error creating new order",
    )
    for authz in order["authorizations"]:
        _do_challenge(challenge_type, authz, nonce_url, auth, account_key, thumbprint)

    # Step 8: Finalize
    csr_der = _cmd(
        ["openssl", "req", "-in", csr, "-outform", "DER"], err_msg="DER Export Error"
    )
    fnlz_resp, fnlz_code, fnlz_headers = _send_signed_request(
        order["finalize"],
        {"csr": _b64(csr_der)},
        nonce_url,
        auth,
        account_key,
        "Error finalizing order",
    )

    # Step 9: Wait for CA to mark test as valid
    sys.stderr.write("Waiting for {0} challenge to pass...\n".format(cn))
    order = _poll_until_not(
        order_headers["Location"],
        ["pending", "processing"],
        nonce_url,
        auth,
        account_key,
        "Error checking order status",
    )

    if order["status"] == "valid":
        sys.stderr.write("Passed {0} challenge!\n".format(cn))
    else:
        raise ValueError("'{0}' challenge did not pass: {1}".format(cn, order))

    # Step 10: Get the certificate.
    sys.stderr.write("Getting certificate...\n")
    signed_pem, _, _ = _send_signed_request(
        order["certificate"],
        None,
        nonce_url,
        auth,
        account_key,
        "Error getting certificate",
    )

    sys.stderr.write("Received certificate!\n")

    return signed_pem


def revoke_crt(ca_url, account_key, crt):
    """Use the ACME protocol to revoke an ssl certificate signed by a
    certificate authority.

    :param string ca_url: Let's Encrypt endpoint.
    :param string account_key: Path to your Let's Encrypt account private key.
    :param string crt: Path to the signed certificate.
    """

    def _a64(a):
        "Shortcut function to go from jwt base64 string to bytes"
        return base64.urlsafe_b64decode(str(a + ("=" * (len(a) % 4))))

    # Step 1: Get account public key
    sys.stderr.write("Reading pubkey file...\n")
    out = _cmd(
        ["openssl", "rsa", "-in", account_key, "-noout", "-text"],
        err_msg="Error reading account public key",
    )

    pub_hex, pub_exp = re.search(
        r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        out.decode("utf8"),
        re.MULTILINE | re.DOTALL,
    ).groups()
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
    reg = {"onlyReturnExisting": True}
    nonce_url = _directory(ca_url)["newNonce"]
    auth = {"jwk": jwk}
    acct_headers = None
    result, code, acct_headers = _send_signed_request(
        _directory(ca_url)["newAccount"],
        reg,
        nonce_url,
        auth,
        account_key,
        "Error getting account info",
    )
    auth = {"kid": acct_headers["Location"]}

    # Step 3: Generate the payload.
    crt_der = _cmd(
        ["openssl", "x509", "-in", crt, "-outform", "DER"], err_msg="DER export error"
    )
    crt_der64 = _b64(crt_der)
    rvk_payload = {
        "certificate": crt_der64,
    }
    _send_signed_request(
        _directory(ca_url)["revokeCert"],
        rvk_payload,
        nonce_url,
        auth,
        account_key,
        "Error revoking certificate",
    )
    sys.stderr.write("Certificate revoked!\n")


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""acmens may be used for getting a new SSL certificate, renewing a
SSL certificate for a domain, and revoking a certificate for a domain.

It's meant to be run locally from your computer.""",
    )
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    parser.add_argument(
        "--revoke", action="store_true", help="Revoke a signed certificate"
    )
    parser.add_argument(
        "--stage", action="store_true", help="Use Let's Encrypt's staging endpoint"
    )
    parser.add_argument(
        "-k",
        "--account-key",
        help="path to your Let's Encrypt account private key",
    )
    parser.add_argument(
        "-e",
        "--email",
        default=None,
        help="contact email, default is webmaster@<shortest_domain>",
    )
    parser.add_argument(
        "-c",
        "--challenge",
        default="http",
        help="Challenge type (http or dns), default is http",
    )
    parser.add_argument("--csr", help="path to your certificate signing request")
    parser.add_argument("--crt", help="path to your signed certificate")

    args = parser.parse_args()
    if args.version:
        print("acmens v{}".format(__version__))
        sys.exit(0)
    if args.account_key is None:
        sys.stderr.write("Error: Path account key is required\n")
        sys.exit(1)
    if (not args.revoke) and (args.csr is None):
        sys.stderr.write("Error: Path to CSR required\n")
        sys.exit(1)
    if args.revoke and args.crt is None:
        sys.stderr.write("Error: Path to signed cert required\n")
        sys.exit(1)

    ca_url = CA_PRD
    if args.stage:
        ca_url = CA_STG

    if args.revoke:
        revoke_crt(ca_url, args.account_key, args.crt)
    else:
        signed_crt = sign_csr(
            ca_url,
            args.account_key,
            args.csr,
            email=args.email,
            challenge_type=args.challenge,
        )
        sys.stdout.write(signed_crt)
