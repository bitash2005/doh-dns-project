# DoH DNS Project

This project is a simple implementation of a DNS server written in Python.  
It supports both traditional DNS over UDP and DNS over HTTPS (DoH).

The goal of this project was to better understand how DNS works internally and how DNS queries can be transferred over HTTPS.

---

## Features

- DNS over UDP
- DNS over HTTPS (GET & POST)
- Basic caching mechanism
- DNS query forwarding
- Simple admin HTTP interface
- CLI testing tool
- Self-signed certificate generation

---

## Project Structure


doh-dns-project/
│
├── src/
│ ├── dns_udp_server.py
│ ├── doh_http.py
│ ├── forwarder.py
│ ├── cache.py
│ ├── records.py
│ ├── admin_http.py
│ ├── cli.py
│ └── test files
│
├── ui/
│ ├── index.html
│ └── app.js


---

## How to Run

### 1. Create virtual environment


python -m venv .venv


Activate it:

Windows:

.venv\Scripts\activate


Linux / Mac:

source .venv/bin/activate


---

### 2. Generate certificate


python src/generate_cert.py


---

### 3. Run UDP DNS server


python src/dns_udp_server.py


---

### 4. Run DoH server


python src/doh_http.py


---

## What I Learned

- Structure of DNS packets
- How DNS over HTTPS works
- Handling SSL in Python
- Working with sockets
- Implementing a basic cache system

---

This project was developed as part of a networking learning exercise.