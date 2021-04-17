# acmens

A fork of [acme-nosudo][]. It uses ACMEv2 protocol and requires Python 3.

[acme-nosudo]: https://github.com/diafygi/acme-nosudo

`acmens` may be used for getting a new SSL certificate, renewing a SSL
certificate for a domain, and revoking a certificate for a domain.

It's meant to be run locally from your computer.

## prerequisites

* openssl or libressl
* python3
* pip

## installation

```sh
pip install acmens
```

## getting/renewing a certificate

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
# Generate domain key
openssl genrsa -aes256 -out domain.key 4096

# Generate CSR
openssl req -new -sha256 -key domain.key -out domain.csr

# Or Generate CSR with multiple domains
openssl req -new -sha256 -key domain.key -subj "/" -addext "subjectAltName = DNS:example.com, DNS:www.example.com" > domain.csr
```

Third, you run the script using python and passing in the path to your user
account private key, email address, and the domain CSR. The paths can be
relative or absolute.

```sh
acmens --account-key user.key --email mail@example.com --csr domain.csr > signed.crt
```

When you run the script, it will:

 - Register you with Let's Encrypt using the email address.

 - If the `user.key` is encrypted, openssl will ask for the passphrase every time
   the private key is used for signing requests or data.

 - Ask you to provision a HTTP resource on your web server for the domain for
   the ACME HTTP challenge.

 - Will write the certificate to `signed.crt` if ACME HTTP challenge is
   successful.

## dns challenge

If you want to use the DNS challenge type provide it using the `--challenge` flag.

```sh
acmens --account-key user.key --email mail@example.com --challenge dns --csr domain.csr > signed.crt
```

This will prompt you to update the DNS records to add a TXT record.

## revoking a certificate

First, you will need to the user account key for Let's Encrypt that was used
when the certificate was signed.

Second, you will need the PEM encoded signed certificate that was produced by
`acmens`.

Third, you run the script using python and passing in the path to your user
account key and the signed domain certificate. The paths can be relative or
absolute.

```sh
acmens --revoke -k user.key --crt domain.crt
```
