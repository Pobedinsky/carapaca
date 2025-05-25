# CarapacaSSH

This is a Portuguese 🇵🇹 SSH, designed for secure remote shell access between different networks. This project replicates core functionality of SSH using a Docker-based setup, making it easy to deploy and run in any OS, the only requirement is to have Docker installed. 


---

## Architecture

The project is composed of three main components: server, client and Trusting Agent. If the server's and client's functions are obvious, the Trusting Agent will allow the public keys exchange between client-server.
The system implements:
- RSA for exchange of a session key
- ECIES for safe encrypt and decrypt
- Preloaded symmetric keys
- Digital Signature for authentication server-client

---

## 🔮 Future Work

Planned enhancements and cryptographic features for future versions of CarapacaSSH include:

- **Implementing the Schnorr Signature Algorithm**  
  For efficient and provably secure digital signatures with strong cryptographic guarantees.

- **Merkle Puzzles Integration**  
  As an experimental feature to explore early public-key cryptographic principles in a modernized context.

- **Shamir’s Secret Sharing**  
  To support distributed key management and secure multi-party authentication schemes.


---
## 📦 Installation

To get started, extract and install the pre-packaged Docker container image.

### Step 1: Download and Extract the Image

1. Download the compressed archive: (carapaca.tar.zip)
2. Unzip the archive
3. This will extract a `.tar` file (Docker image archive).

### Step 2: Load the Docker Image

Use Docker to load the image from the `.tar` file:

```bash
docker load < carapacatar.tar
```


