# CarapacaSSH

This is a Portuguese 🇵🇹 SSH, designed for secure remote shell access between different networks. This project replicates core functionality of SSH using a Docker-based setup, making it easy to deploy and run in any OS, the only requirement is to have Docker installed. 


---

## 🧱 Architecture

The project is composed of three main components:

- **Client** – Initiates a secure connection request and handles local encryption/decryption tasks.
- **Server** – Responds to connection requests, manages authentication, and establishes a secure session.
- **Trusting Agent** – A mediator responsible for securely exchanging public keys between the client and server, ensuring both parties can trust each other before communication begins.

---

### 🔐 Cryptographic Components

The system implements a layered security model using multiple cryptographic techniques:

- **RSA** – Used for the exchange of a symmetric session key between client and server.
- **ECIES (Elliptic Curve Integrated Encryption Scheme)** – Ensures confidentiality during data encryption and decryption processes.
- **Preloaded Symmetric Keys** – Shared keys are distributed securely in advance and used for fast symmetric encryption.
- **Digital Signatures** – Provides mutual authentication between client and server to prevent impersonation and ensure data integrity.

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


