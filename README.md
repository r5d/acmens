# ACME Without Sudo

The [Let's Encrypt](https://letsencrypt.org/) initiative is a fantastic program
that offers **free** https certificates! However, the one catch is that you need
to use their command program to get a free certificate. The default instructions
all assume that you will run it on your your server as root, and that it will
edit your apache/nginx config files.

I love the Let's Encrypt devs dearly, but there's no way I'm going to trust
their script to run on my server as root, be able to edit my server configs, and
have access to my private keys. I'd just like the free ssl certificate, please.

So I made a script that does that. You generate your private key and certificate
signing request (CSR) like normal, then run `sign_csr.py` with your CSR to get
it signed. The script goes through the [ACME protocol](https://github.com/ietf-wg-acme/acme/)
with the Let's Encrypt certificate authority and outputs the signed certificate
to stdout.

This script is meant to be run on your computer locally. It requires you to pass
your account private key. If the account private key is encrypted, openssl will
directly ask for the passphrase each time the private key is needed to sign
requests or data.

## Table of Contents

* [Donate](#donate)
* [Prerequisites](#prerequisites)
* Signing script
    * [How to use the signing script](#how-to-use-the-signing-script)
    * [Example use of the signing script](#example-use-of-the-signing-script)
    * [How to use the signed https certificate](#how-to-use-the-signed-https-certificate)
    * [Demo](#demo)
* Revocation script
    * [How to use the revocation script](#how-to-use-the-revocation-script)
    * [Example use of the revocation script](#example-use-of-the-revocation-script)
* [Alternative: Official Let's Encrypt Client](#alternative-official-lets-encrypt-client)
* [Feedback/Contributing](#feedbackcontributing)

## Donate

If this script is useful to you, please donate to the EFF. I don't work there,
but they do fantastic work.

[https://eff.org/donate/](https://eff.org/donate/)

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
python3 sign_csr.py --account-key user.key --email mail@example.com domain.csr > signed.crt
```

When you run the script, it will:

 - Register you with Let's Encrypt using the email address.

 - If the `user.key` is encrypted, openssl will ask for the passphrase every time
   the private key is used for signing requests or data.

 - Ask you to provision a HTTP resource on your web server for the domain for
   the ACME HTTP challenge.

 - Will write the certificate to `signed.crt` if ACME HTTP challenge is
   successful.

### Help text
```
user@hostname:~$ python3 sign_csr.py --help
usage: sign_csr.py [-h] -k ACCOUNT_KEY [-e EMAIL] csr_path

Get a SSL certificate signed by a Let's Encrypt (ACME) certificate
authority and output that signed certificate. You do NOT need to run
this script on your server, it is meant to be run on your
computer. The script will request you to manually deploy the acme
challenge on your server.

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
$ python3 sign_csr.py --account-key user.key --email user@example.com domain.csr > signed.crt
--------------

positional arguments:
  csr_path              path to your certificate signing request

optional arguments:
  -h, --help            show this help message and exit
  -k ACCOUNT_KEY, --account-key ACCOUNT_KEY
                        path to your Let's Encrypt account private key
  -e EMAIL, --email EMAIL
                        contact email, default is webmaster@<shortest_domain>
user@hostname:~$
```

## Example use of the signing script

### Commands (what you do in your main terminal window)
```
user@hostname:~$ openssl genrsa -aes256 4096 > user.key
Generating RSA private key, 4096 bit long modulus
.....................................++++
...................................................++++
e is 65537 (0x10001)
Enter pass phrase:
Verifying - Enter pass phrase:
user@hostname:~$ openssl genrsa -aes256 4096 > domain.key
Generating RSA private key, 4096 bit long modulus
................................................++++
.................................................................................................................++++
e is 65537 (0x10001)
Enter pass phrase:
Verifying - Enter pass phrase:
user@hostname:~$ openssl req -new -sha256 -key domain.key -subj "/CN=letsencrypt.daylightpirates.org" > domain.csr
Enter pass phrase for domain.key:
user@hostname:~$ python3 sign_csr.py -k user.key -e daniel@roesler.cc domain.csr > chained.pem
Reading pubkey file...
Enter pass phrase for user.key:
Found public key!
Reading csr file...
Found domains letsencrypt.daylightpirates.org
Registering daniel@roesler.cc...
Enter pass phrase for user.key:
Already registered!
Making new order for letsencrypt.daylightpirates.org...
Enter pass phrase for user.key:
Requesting challenges...
Enter pass phrase for user.key:
Please update your server to serve the following file at this URL:

--------------
URL: http://letsencrypt.daylightpirates.org/.well-known/acme-challenge/fcGheyb6yNjSQ7oQ3hFXZqCRpKHrkeq9eBFOcloAO_k
File contents: "fcGheyb6yNjSQ7oQ3hFXZqCRpKHrkeq9eBFOcloAO_k.aY_r0djPrHVGZ6MONmcsSN84_mUmUtHydtPGFq7LKWY"
--------------

Notes:
- Do not include the quotes in the file.
- The file should be one line without any spaces.

Press Enter when you've got the file hosted on your server...
Requesting verification for letsencrypt.daylightpirates.org...
Enter pass phrase for user.key:
Enter pass phrase for user.key:
letsencrypt.daylightpirates.org verified!
Enter pass phrase for user.key:
Waiting for letsencrypt.daylightpirates.org challenge to pass...
Enter pass phrase for user.key:
Passed letsencrypt.daylightpirates.org challenge!
Getting certificate...
Enter pass phrase for user.key:
Received certificate!
You can remove the acme-challenge file from your webserver now.
user@hostname:~$ cat chained.pem
-----BEGIN CERTIFICATE-----
MIIGJTCCBQ2gAwIBAgISATBRUGjFwTtjF4adpF7zd/5qMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMTAeFw0xNTEwMjQwOTU4MDBaFw0x
NjAxMjIwOTU4MDBaMCoxKDAmBgNVBAMTH2xldHNlbmNyeXB0LmRheWxpZ2h0cGly
YXRlcy5vcmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2Ac7twhMz
AxreQxmlY0gBq20zrriMOCLTwwdJ3sfv9bNxo+iG7eidu9imLI0FNjZkxtpyJeG/
+4OnvTgChHiTEKtD0Q3SoeSOu3Bl73d4bVBfTsvj0yEoMrF4Y89VvqbH7HP+2evv
Uraj2Qv0EUor3KAsOJW4hiSQedmz69+3IVZHWdpyYTtC1HjO9C5DqPgD7hlrtRrP
k0SL4j048NIiDvMm36pzn/UM+HxuavVxIyQ7BigDk7Hev6jXH2BqQk0ADtR0CycI
nJeS5gk+i6ImDeOsrhPrXvub02aRbol/paoSknskAOJKe4628dd873QfMXnQz1JT
aggaFQA1S8M2DY9l574/gOH39BudXdvOGzln7MeDJoi7Tybih2FJJbj8tQPV2zwh
ArbKLHPJibM1HP8jc7QQcrWnNf3H2N5FhP8uvEVchdYk3zV2tJPqlQnsHctOjNrV
18WRsl+JpUNLclRWQ3JLYZL+waIaJvsAsjp58J3XK1PI1s7QPuJpI3u7hlu4zz2e
TMF8OqAEy+rkHML5j+ncB+ctxhgNgirwpCUQ3NL9rslte0OmO+kzjrVfJ7o5D6zt
Hn5xg2WTgNoCdXbIruEzC43SqkPIH8VeFkzjPCqGajQsXXmdbDyoNkJ+SK0Fz0hI
3alW4kaOSe0aeto22sKtOjsIy7GF6qDw4QIDAQABo4ICIzCCAh8wDgYDVR0PAQH/
BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8E
AjAAMB0GA1UdDgQWBBSpGhk6yOALnLPWzrncMA/wnd6nNzAfBgNVHSMEGDAWgBSo
SmpjBH3duubRObemRWXv86jsoTBwBggrBgEFBQcBAQRkMGIwLwYIKwYBBQUHMAGG
I2h0dHA6Ly9vY3NwLmludC14MS5sZXRzZW5jcnlwdC5vcmcvMC8GCCsGAQUFBzAC
hiNodHRwOi8vY2VydC5pbnQteDEubGV0c2VuY3J5cHQub3JnLzAqBgNVHREEIzAh
gh9sZXRzZW5jcnlwdC5kYXlsaWdodHBpcmF0ZXMub3JnMIIBAAYDVR0gBIH4MIH1
MAoGBmeBDAECATAAMIHmBgsrBgEEAYLfEwEBATCB1jAmBggrBgEFBQcCARYaaHR0
cDovL2Nwcy5sZXRzZW5jcnlwdC5vcmcwgasGCCsGAQUFBwICMIGeDIGbVGhpcyBD
ZXJ0aWZpY2F0ZSBtYXkgb25seSBiZSByZWxpZWQgdXBvbiBieSBSZWx5aW5nIFBh
cnRpZXMgYW5kIG9ubHkgaW4gYWNjb3JkYW5jZSB3aXRoIHRoZSBDZXJ0aWZpY2F0
ZSBQb2xpY3kgZm91bmQgYXQgaHR0cHM6Ly9sZXRzZW5jcnlwdC5vcmcvcmVwb3Np
dG9yeS8wDQYJKoZIhvcNAQELBQADggEBADQ2nWJa0jSOgStC7luKLmNOiNZTbiYP
ITFetj6WpRIsAHwz3vTwDIWFtczrhksWRTU9mCIwaxtqflZrirc3mE6jKugeSUHr
1yqTXZ097rDNAnMvUtvoET/UBkAU+gUDn8zRFtKOePuWX7P8qHq8QqjNqMC0vb5s
ncyFqSSZl1j9e5l+Kpj/GeTCwkwck5U75Ry44kPbnu5JLd70P724gBnyEi6IxXHB
txXZEUmI0R1Ee3Kw/5N6JfeWNE1KEmM47VVFomRitruxBj9nlXtIILvkPCTWkDua
pr1OmFi/rUcaHw+Txbs8aBmZEBkxy9HPSfgqqlYqEd0ipGqFtqaFJEI=
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----
user@hostname:~$
```

### Server Commands (the stuff the script asked you to do on your server)
```
ubuntu@letsencrypt.daylightpirates.org:~$ cd /var/www/root
ubuntu@letsencrypt.daylightpirates.org:/var/www/root$ mkdir -p .well-known/acme-challenge/
ubuntu@letsencrypt.daylightpirates.org:/var/www/root$ echo "fcGheyb6yNjSQ7oQ3hFXZqCRpKHrkeq9eBFOcloAO_k.aY_r0djPrHVGZ6MONmcsSN84_mUmUtHydtPGFq7LKWY" > .well-known/acme-challenge/fcGheyb6yNjSQ7oQ3hFXZqCRpKHrkeq9eBFOcloAO_k
ubuntu@letsencrypt.daylightpirates.org:/var/www/root$
```

## How to use the signed https certificate

The signed https certificate that is output by this script can be used along
with your private key to run an https server. You just securely transfer (using
`scp` or similar) the private key and signed certificate to your server, then
include them in the https settings in your web server's configuration. Here's an
example on how to configure an nginx server:

An unencrypted version of the domain private key needs to be deployed on the
server, to decrypt domain private key do:

```
openssl rsa -in domain.key -out domain.d.key
```

```nginx
server {
    listen 443;
    server_name letsencrypt.daylightpirates.org;
    ssl on;
    ssl_certificate chained.pem;
    ssl_certificate_key domain.d.key;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA;
    ssl_session_cache shared:SSL:50m;
    ssl_dhparam /etc/nginx/server.dhparam;
    ssl_prefer_server_ciphers on;

    location / {
        return 200 'Let\'s Encrypt Example: https://github.com/diafygi/acme-nosudo';
        add_header Content-Type text/plain;
    }
}
```

## Demo

Here's a website that is using a certificate signed using `sign_csr.py`:

[https://letsencrypt.daylightpirates.org/](https://letsencrypt.daylightpirates.org/)

## How to use the revocation script

First, you will need to the user account key for Let's Encrypt that was used
when the certifacate was signed.

Second, you will need the PEM encoded signed certificate that was produced by
`sign_csr.py`.

Third, you run the script using python and passing in the path to your user
account key and the signed domain certificate. The paths can be relative or
absolute.

```sh
python3 revoke_crt.py -k user.key domain.crt
```

### Help text
```
user@hostname:~$ python3 revoke_crt.py --help
usage: revoke_crt.py [-h] -k ACCOUNT_KEY crt_path

Get a SSL certificate revoked by a Let's Encrypt (ACME) certificate
authority.  You do NOT need to run this script on your server, it is
meant to be run on your computer.

NOTE: YOUR PUBLIC KEY NEEDS TO BE THE SAME KEY USED TO ISSUE THE CERTIFICATE.

Prerequisites:
* openssl
* python 3

Example:
--------------
$ python3 revoke_crt.py --public-key user.pub domain.crt
--------------

positional arguments:
  crt_path              path to your signed certificate

optional arguments:
  -h, --help            show this help message and exit
  -k ACCOUNT_KEY, --account-key ACCOUNT_KEY
                        path to your Let's Encrypt account private key
user@hostname:~$
```

## Example use of the revocation script

### Commands (what you do in your main terminal window)
```
user@hostname:~$ python3 revoke_crt.py --public-key user.pub domain.crt
Reading pubkey file...
Found public key!
STEP 1: You need to sign a file (replace 'user.key' with your user private key)

openssl dgst -sha256 -sign user.key -out revoke_Z5Qxj3.sig revoke_TKSK9w.json

Press Enter when you've run the above command in a new terminal window...
Requesting revocation...
Certificate revoked!
user@hostname:~$
```

### Manual Command (the stuff the script asked you to do in a 2nd terminal)
```
#signed files
user@hostname:~$ openssl dgst -sha256 -sign user.key -out revoke_Z5Qxj3.sig revoke_TKSK9w.json
```

## Alternative: Official Let's Encrypt Client

After I released this script, Let's Encrypt added a manual authenticator to
allow the Let's Encrypt client to not have to be run on your server. Hooray!
However, the Let's Encrypt client still has access to your user account private
keys, so please be aware of that. Anyway, check out the comment on issue
[#5](https://github.com/diafygi/acme-nosudo/issues/5#issuecomment-117283651)
to see how to use the manual authenticator in the official Let's Encrypt client.

```
./letsencrypt-auto --email diafygi@gmail.com --text --authenticator manual --work-dir /tmp/work/ --config-dir /tmp/config/ --logs-dir /tmp/logs/ auth --cert-path /tmp/certs/ --chain-path /tmp/chains/ --csr ~/Desktop/domain.csr
```

## Feedback/Contributing

I'd love to receive feedback, issues, and pull requests to make this script
better. The script itself, `sign_csr.py`, is less than 500 lines of code, so
feel free to read through it! I tried to comment things well and make it crystal
clear what it's doing.

For example, it currently can't do any ACME challenges besides 'http-01'. Maybe
someone could do a pull request to add more challenge compatibility?


