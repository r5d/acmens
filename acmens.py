# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: AGPL-3.0-only
#
# Copyright © 2015-2018 Daniel Roesler <diafygi@gmail.com>
# Copyright © 2021 siddharth <s@ricketyspace.net>
#

import argparse, subprocess, json, os, urllib.request, sys, base64, binascii, time, hashlib, tempfile, re, copy, textwrap

from urllib.request import urlopen
from urllib.error import HTTPError


__version__ = "0.1.4"


def sign_csr(account_key, csr, email=None, challenge_type="http"):
    """Use the ACME protocol to get an ssl certificate signed by a
    certificate authority.

    :param string account_key: Path to the user account key.
    :param string csr: Path to the certificate signing request.
    :param string email: An optional user account contact email
                         (defaults to webmaster@<shortest_domain>)
    :param string challenge_type: The challenge type to use.
                         (defaults to http)

    :returns: Signed Certificate (PEM format)
    :rtype: string

    """
    # CA = "https://acme-staging-v02.api.letsencrypt.org"
    CA = "https://acme-v02.api.letsencrypt.org"
    DIRECTORY = json.loads(urlopen(CA + "/directory").read().decode("utf8"))

    def _b64(b):
        "Shortcut function to go from bytes to jwt base64 string"
        if type(b) is str:
            b = b.encode()

        return base64.urlsafe_b64encode(b).decode().replace("=", "")

    # helper function - run external commands
    def _cmd(cmd_list, stdin=None, cmd_input=None, err_msg="Command Line Error"):
        proc = subprocess.Popen(
            cmd_list, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = proc.communicate(cmd_input)
        if proc.returncode != 0:
            raise IOError("{0}\n{1}".format(err_msg, err))
        return out

    # helper function - make request and automatically parse json response
    def _do_request(url, data=None, err_msg="Error", depth=0):
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
        except IOError as e:
            resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
            code, headers = getattr(e, "code", None), {}
        try:
            resp_data = json.loads(resp_data)  # try to parse json results
        except ValueError:
            pass  # ignore json parsing errors
        if (
            depth < 100
            and code == 400
            and resp_data["type"] == "urn:ietf:params:acme:error:badNonce"
        ):
            raise IndexError(resp_data)  # allow 100 retrys for bad nonces
        if code not in [200, 201, 204]:
            raise ValueError(
                "{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(
                    err_msg, url, data, code, resp_data
                )
            )
        return resp_data, code, headers

    # helper function - make signed requests
    def _send_signed_request(url, payload, err_msg, depth=0):
        payload64 = "" if payload is None else _b64(json.dumps(payload).encode("utf8"))
        new_nonce = _do_request(DIRECTORY["newNonce"])[2]["Replay-Nonce"]
        protected = {"url": url, "alg": "RS256", "nonce": new_nonce}
        protected.update(
            {"jwk": jwk} if acct_headers is None else {"kid": acct_headers["Location"]}
        )
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        protected_input = "{0}.{1}".format(protected64, payload64).encode("utf8")
        out = _cmd(
            ["openssl", "dgst", "-sha256", "-sign", account_key],
            stdin=subprocess.PIPE,
            cmd_input=protected_input,
            err_msg="OpenSSL Error",
        )
        data = json.dumps(
            {"protected": protected64, "payload": payload64, "signature": _b64(out)}
        )
        try:
            return _do_request(
                url, data=data.encode("utf8"), err_msg=err_msg, depth=depth
            )
        except IndexError:  # retry bad nonces (they raise IndexError)
            return _send_signed_request(url, payload, err_msg, depth=(depth + 1))

    # helper function - poll until complete
    def _poll_until_not(url, pending_statuses, err_msg):
        result, t0 = None, time.time()
        while result is None or result["status"] in pending_statuses:
            assert time.time() - t0 < 3600, "Polling timeout"  # 1 hour timeout
            time.sleep(0 if result is None else 2)
            result, _, _ = _send_signed_request(url, None, err_msg)
        return result

    # helper function - do challenge
    def _do_challenge(authz_url, thumbprint):
        # Request challenges
        sys.stderr.write("Requesting challenges...\n")
        chl_result, chl_code, chl_headers = _send_signed_request(
            authz_url, None, "Error getting challenges"
        )
        domain = chl_result["identifier"]["value"]

        # Choose challenge.
        preferred_type = "dns-01" if challenge_type == "dns" else "http-01"
        challenge = None
        http_challenge = None
        for c in chl_result["challenges"]:
            if c["type"] == preferred_type:
                challenge = c
            if c["type"] == "http-01":
                http_challenge = c
        if challenge is None:
            if http_challenge is None:
                sys.stderr.write("Error: Unable to find challenges!")
                sys.exit(1)
            challenge = http_challenge  # Fallback to http challenge.
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
            "Error requesting challenge verfication: {0}".format(domain),
        )
        chl_verification = _poll_until_not(
            challenge["url"], ["pending"], "Error checking challenge verification"
        )
        if chl_verification["status"] != "valid":
            raise ValueError(
                "Challenge did not pass for {0}: {1}".format(domain, chl_verification)
            )
        sys.stderr.write("{} verified!\n".format(domain))

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
    reg = {"termsOfServiceAgreed": True}
    acct_headers = None
    result, code, acct_headers = _send_signed_request(
        DIRECTORY["newAccount"], reg, "Error registering"
    )
    if code == 201:
        sys.stderr.write("Registered!\n")
    else:
        sys.stderr.write("Already registered!\n")

    # Step 5: Request challenges for domains
    sys.stderr.write("Making new order for {0}...\n".format(", ".join(domains)))
    id = {"identifiers": []}
    for domain in domains:
        id["identifiers"].append({"type": "dns", "value": domain})
    order, order_code, order_headers = _send_signed_request(
        DIRECTORY["newOrder"], id, "Error creating new order"
    )
    for authz in order["authorizations"]:
        _do_challenge(authz, thumbprint)

    # Step 8: Finalize
    csr_der = _cmd(
        ["openssl", "req", "-in", csr, "-outform", "DER"], err_msg="DER Export Error"
    )
    fnlz_resp, fnlz_code, fnlz_headers = _send_signed_request(
        order["finalize"], {"csr": _b64(csr_der)}, "Error finalizing order"
    )

    # Step 9: Wait for CA to mark test as valid
    sys.stderr.write("Waiting for {0} challenge to pass...\n".format(cn))
    order = _poll_until_not(
        order_headers["Location"],
        ["pending", "processing"],
        "Error checking order status",
    )

    if order["status"] == "valid":
        sys.stderr.write("Passed {0} challenge!\n".format(cn))
    else:
        raise ValueError("'{0}' challenge did not pass: {1}".format(cn, order))

    # Step 10: Get the certificate.
    sys.stderr.write("Getting certificate...\n")
    signed_pem, _, _ = _send_signed_request(
        order["certificate"], None, "Error getting certificate"
    )

    sys.stderr.write("Received certificate!\n")
    sys.stderr.write(
        "You can remove the acme-challenge file from your webserver now.\n"
    )

    return signed_pem


def revoke_crt(account_key, crt):
    """Use the ACME protocol to revoke an ssl certificate signed by a
    certificate authority.

    :param string account_key: Path to your Let's Encrypt account private key.
    :param string crt: Path to the signed certificate.
    """
    # CA = "https://acme-staging-v02.api.letsencrypt.org"
    CA = "https://acme-v02.api.letsencrypt.org"
    DIRECTORY = json.loads(urlopen(CA + "/directory").read().decode("utf8"))

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
        proc = subprocess.Popen(
            cmd_list, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = proc.communicate(cmd_input)
        if proc.returncode != 0:
            raise IOError("{0}\n{1}".format(err_msg, err))
        return out

    # helper function - make request and automatically parse json response
    def _do_request(url, data=None, err_msg="Error", depth=0):
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
        except IOError as e:
            resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
            code, headers = getattr(e, "code", None), {}
        try:
            resp_data = json.loads(resp_data)  # try to parse json results
        except ValueError:
            pass  # ignore json parsing errors
        if (
            depth < 100
            and code == 400
            and resp_data["type"] == "urn:ietf:params:acme:error:badNonce"
        ):
            raise IndexError(resp_data)  # allow 100 retrys for bad nonces
        if code not in [200, 201, 204]:
            raise ValueError(
                "{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(
                    err_msg, url, data, code, resp_data
                )
            )
        return resp_data, code, headers

    # helper function - make signed requests
    def _send_signed_request(url, payload, err_msg, depth=0):
        payload64 = "" if payload is None else _b64(json.dumps(payload).encode("utf8"))
        new_nonce = _do_request(DIRECTORY["newNonce"])[2]["Replay-Nonce"]
        protected = {"url": url, "alg": "RS256", "nonce": new_nonce}
        protected.update(
            {"jwk": jwk} if acct_headers is None else {"kid": acct_headers["Location"]}
        )
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        protected_input = "{0}.{1}".format(protected64, payload64).encode("utf8")
        out = _cmd(
            ["openssl", "dgst", "-sha256", "-sign", account_key],
            stdin=subprocess.PIPE,
            cmd_input=protected_input,
            err_msg="OpenSSL Error",
        )
        data = json.dumps(
            {"protected": protected64, "payload": payload64, "signature": _b64(out)}
        )
        try:
            return _do_request(
                url, data=data.encode("utf8"), err_msg=err_msg, depth=depth
            )
        except IndexError:  # retry bad nonces (they raise IndexError)
            return _send_signed_request(url, payload, err_msg, depth=(depth + 1))

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
    reg = {"onlyReturnExistiing": True}
    acct_headers = None
    result, code, acct_headers = _send_signed_request(
        DIRECTORY["newAccount"], reg, "Error getting account info"
    )

    # Step 3: Generate the payload.
    crt_der = _cmd(
        ["openssl", "x509", "-in", crt, "-outform", "DER"], err_msg="DER export error"
    )
    crt_der64 = _b64(crt_der)
    rvk_payload = {
        "certificate": crt_der64,
    }
    _send_signed_request(
        DIRECTORY["revokeCert"], rvk_payload, "Error revoking certificate"
    )
    sys.stderr.write("Certificate revoked!\n")


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""\
Get a SSL certificate signed by a Let's Encrypt (ACME) certificate
authority and output that signed certificate. You do NOT need to run
this script on your server, it is meant to be run on your
computer. The script will request you to manually deploy the acme
challenge on your server.

You may also revoke a signed Let's Encrypt (ACME) certificate.


NOTE: YOUR ACCOUNT KEY NEEDS TO BE DIFFERENT FROM YOUR DOMAIN KEY.

Prerequisites:
* openssl
* python version 3

Example: Generate an account keypair, a domain key and csr, and have the domain csr signed.
--------------
$ openssl genrsa -aes256 4096 > user.key
$ openssl rsa -in user.key -pubout > user.pub
$ openssl genrsa -aes256 4096 > domain.key
$ openssl req -new -sha256 -key domain.key -subj "/CN=example.com" > domain.csr
$ acmens --account-key user.key --email user@example.com --csr domain.csr > signed.crt
--------------

Example: Revoking a signed certificate:
--------------
$ acmens --revoke --account-key user.key --crt domain.crt
--------------
""",
    )
    parser.add_argument(
        "--revoke", action="store_true", help="Revoke a signed certificate"
    )
    parser.add_argument(
        "-k",
        "--account-key",
        required=True,
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
    if (not args.revoke) and (args.csr is None):
        sys.stderr.write("Error: Path to CSR required\n")
        sys.exit(1)
    if args.revoke and args.crt is None:
        sys.stderr.write("Error: Path to signed cert required\n")
        sys.exit(1)

    if args.revoke:
        revoke_crt(args.account_key, args.crt)
    else:
        signed_crt = sign_csr(
            args.account_key, args.csr, email=args.email, challenge_type=args.challenge
        )
        sys.stdout.write(signed_crt)


if __name__ == "__main__":
    main()
