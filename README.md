# dummycert

A tool to create a full cert chain for debug purpose (including root CA, middle CA, server leaf, client leaf)

## Usage

```bash
dummycert create-chain --dir out --server-dns-name localhost --server-dns-name example.com
```

This will create these files at `out` directory:

```
# root certificate authority
rootca.crt.pem
rootca.key.pem

# middle certificate authority
middle.crt.pem
middle.key.pem

# server leaf certificate
server.crt.pem
server.full-crt.pem
server.key.pem

# client leaf certificate
client.crt.pem
client.full-crt.pem
client.key.pem
```

## License

GUO YANKE, MIT License
