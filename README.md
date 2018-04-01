# FTPS
FTP over SSL Server and Client

## 1. Generate Certificates
```bash
#gen local CA's key: rootkey.pem and certreq: rootreq.pem with passwd: ftps
openssl req -newkey rsa:1024 -sha1 -keyout rootkey.pem -out rootreq.pem -config root.cnf

#gen local CA's cert: rootcert.pem
openssl x509 -req -in rootreq.pem -sha1 -extfile root.cnf -extensions certificate_extensions -signkey rootkey.pem -out rootcert.pem

#bind local CA's cert & key
cat rootcert.pem rootkey.pem > root.pem

#gen serverCA's key: serverCAkey.pem and serverCA's certreq: serverCAreq.pem with key:ftpsserverca
openssl req -newkey rsa:1024 -sha1 -keyout serverCAkey.pem -out serverCAreq.pem -config serverCA.cnf

#local issue serverCA cert:serverCAcert.pem
openssl x509 -req -in serverCAreq.pem -sha1 -extfile serverCA.cnf -extensions certificate_extensions -CA root.pem -CAkey root.pem -CAcreateserial -out serverCAcert.pem

#bind serverCA's cert chain.
cat serverCAcert.pem serverCAkey.pem rootcert.pem >serverCA.pem

#gen server's key:serverkey.pem & certreq:serverreq.pem with key:ftpsserver
openssl req -newkey rsa:1024 -sha1 -keyout serverkey.pem -out serverreq.pem -config server.cnf -reqexts req_extensions

#serverCA issue server cert: servercert.pem
openssl x509 -req -in serverreq.pem -sha1 -extfile server.cnf -extensions certificate_extensions -CA serverCA.pem -CAkey serverCA.pem -CAcreateserial -out servercert.pem

#bind server's cert chain:
cat servercert.pem serverkey.pem serverCAcert.pem rootcert.pem > server.pem

#gen client's key: clientkey.pem and certreq: clientreq.pem with key:ftpsclient
openssl req -newkey rsa:1024 -sha1 -keyout clientkey.pem -out clientreq.pem -config client.cnf -reqexts req_extensions

#local CA issue client cert: clientcert.pem
openssl x509 -req -in clientreq.pem -sha1 -extfile client.cnf -extensions certificate_extensions -CA root.pem -CAkey root.pem -CAcreateserial -out clientcert.pem

#client's cert chain
cat clientcert.pem clientkey.pem rootcert.pem > client.pem

```
## 2. generate DH paramenter
dh512.pem & dh124.pem must be set into a absolut path, i.e., `/opt/`

```bash
#dh512
openssl dhparam -check -text -5 512 -out dh512.pem
#dh1024
openssl dhparam -check -text -5 1024 -out dh1024.pem
```

## 3. compile
```bash
cd server
gcc -DSERVER  -DDHPATH="\"/opt/\"" -g -o server *.c ../*.c -lssl -lcrypto

cd client
gcc -g -o client *.c ../*.c -lssl -lcrypto
```
