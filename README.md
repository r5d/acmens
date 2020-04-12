# acmens

A fork of [acme-nosudo][]. It uses ACMEv2 protocol and requires Python 3.

[acme-nosudo]: https://github.com/diafygi/acme-nosudo

acmens has two scripts:

 - acmens.py
 - revoke_crt.py

The `acmens.py` is for getting a new SSL certificate or renewing a
SSL certificate for a domain.

The `revoke_crt.py` is for revoking a certificate for a domain.

Both scripts are meant to be run locally from your computer.

## Prerequisites

* openssl
* python3

## How to use the signing script

First, you need to generate an user account key for Let's Encrypt.
This is the key that you use to register with Let's Encrypt. If you
already have user account key with Let's Encrypt, you can skip this
step.

```sh
openssl genrsa -aes256 4096 > user.key
openssl rsa -in user.key -pubout > user.pub
```

Second, you need to generate the domain key and a certificate request.
This is the key that you will get signed for free for your domain (replace
"example.com" with the domain you own). If you already have a domain key
and CSR for your domain, you can skip this step.

```sh
#Create a CSR for example.com
openssl genrsa -aes256 4096 > domain.key
openssl req -new -sha256 -key domain.key -subj "/CN=example.com" > domain.csr

#Alternatively, if you want both example.com and www.example.com
openssl genrsa -aes256 4096 > domain.key
openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:example.com,DNS:www.example.com")) > domain.csr
```

Third, you run the script using python and passing in the path to your user
account private key, email address, and the domain CSR. The paths can be
relative or absolute.

```sh
python3 acmens.py --account-key user.key --email mail@example.com domain.csr > signed.crt
```

When you run the script, it will:

 - Register you with Let's Encrypt using the email address.

 - If the `user.key` is encrypted, openssl will ask for the passphrase every time
   the private key is used for signing requests or data.

 - Ask you to provision a HTTP resource on your web server for the domain for
   the ACME HTTP challenge.

 - Will write the certificate to `signed.crt` if ACME HTTP challenge is
   successful.

## How to use the revocation script

First, you will need to the user account key for Let's Encrypt that was used
when the certifacate was signed.

Second, you will need the PEM encoded signed certificate that was produced by
`acmens.py`.

Third, you run the script using python and passing in the path to your user
account key and the signed domain certificate. The paths can be relative or
absolute.

```sh
python3 revoke_crt.py -k user.key domain.crt
```
