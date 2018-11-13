# OpenAlias Rest Api

The OpenAlias Rest Api (OAR) seeks to allow web application to take advantage of OpenAlias while we wait for DNSSec to be implemented everywhere. The REST Api generates a signed request so that web apps can perform a DNS lookup and be guaranteed the results came from a server they trust, one that can properly verify integrity the of the lookup with DNSSec.

## Generate Keys

If you want to run your own instance of the OpenAlias Rest Api then you need to generate some keys to use.

```
sudo openssl req -newkey rsa:2048 -nodes -keyout /etc/ssl/oar.key -x509 -days 365 -out /etc/ssl/oar.crt
```

```
writing new private key to '/etc/ssl/oar.key'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) []:CA
State or Province Name (full name) []:Ontario
Locality Name (eg, city) []:Ottawa
Organization Name (eg, company) []:Outdoor Devs
Organizational Unit Name (eg, section) []:OpenAlias Rest Api
Common Name (eg, fully qualified host name) []:oar.outdoordevs.com
Email Address []:support@outdoordevs.com
```


## References Used

https://openalias.org/#extend
https://kjur.github.io/jsrsasign/
https://kjur.github.io/jsrsasign/sample/sample-rsasign.html
https://github.com/kjur/jsrsasign/wiki/Tutorial-for-Signature-class
https://kjur.github.io/jsrsasign/api/symbols/KJUR.crypto.Signature.html
https://developers.google.com/speed/public-dns/docs/dns-over-https
https://wiki.parity.io/JSONRPC-personal-module#personal_sign
https://wiki.parity.io/JSONRPC-personal-module#personal_ecrecover
http://restify.com/docs/home

