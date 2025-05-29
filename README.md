# mTLS Certificate Generator

This project is a simple tool written in Go that helps you generate self-signed mTLS (Mutual TLS) certificates. It’s designed for local development and testing, making it easy to set up your own certificate authority (CA) along with server and client certificates, perfect for testing secure connections without relying on external certificate providers.
## What does it do?

- Creates a **self-signed Certificate Authority (CA)**.
- Generates certificates for a **server** and a **client**, signed by the CA.
- Associates multiple IPs (e.g., `127.0.0.1`, `192.168.x.x`, etc.) and DNS names (e.g. `humanjuan.com`) to the certificates.
- Saves all files in an organized structure:

```
certificates/
├── ca/
│   ├── ca-cert.pem
│   └── ca-key.pem
├── server/
│   ├── server-cert.pem
│   └── server-key.pem
└── client/
    ├── client-cert.pem
    └── client-key.pem
```

---

## How to use

### 1. Build the project

```bash
go build -o mtlsgen mTLS.go
```

### 2. Run the generator

```bash
./mtlsgen
```

This will generate all certificates in the `./certificates/` folder.

---

## Configuration
You can adjust how the tool works by modifying the global settings in the `mTLS.go` file:

```go
ORG         = "HumanJuan by Juan Alejandro"
COUNTRY     = "Chile"
CITY        = "Linares"
EMAIL       = "juan.alejandro@humanjuan.com"
DNS_NAMES   = []string{"humanjuan.com"}
HOST_IPS    = []string{"127.0.0.1"}
```

You can also add more IPs dynamically using the `generateIPs` function.

---

## Use cases

- Local development with HTTPS servers that require mutual authentication.
- Testing services that implement **mTLS** like Grafana, Prometheus, Nginx, etc.
- Projects with custom servers like [Golyn](https://github.com/jpengineer/golyn) or other APIs.

---

## License

MIT © Juan Alejandro Pérez Chandia - [humanjuan.com](https://humanjuan.com)