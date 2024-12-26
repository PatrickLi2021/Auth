# Auth

This repository contains the code for a secure authentication platform that involves two primary programs: a server and a client. The server acts as the central authority for verifying clients, issuing digital certificates, and ensuring secure communication between clients. The authentication system utilizes digital signatures, password-based authentication, two-factor authentication (2FA), and authenticated key exchange to secure the platform against impersonation and man-in-the-middle attacks.

## Background Knowledge

This project is built around several key cryptographic principles, including digital signatures, password authentication, and two-factor authentication (2FA). Here’s a breakdown of these concepts:

### Digital Signatures

Digital signatures enable secure message verification. A keypair consisting of a public **verification key** (vk) and a secret **signing key** (sk) is used. The secret key is used to sign messages, while the public key allows others to verify the authenticity of the signed message. The security of digital signatures relies on the difficulty of forging signatures even when the public key is known.

### Password Authentication

The platform uses a secure password authentication protocol to protect user credentials. Instead of sending passwords directly over the network or storing them in plaintext, the server uses a series of cryptographic techniques:

1. **Salting:** A random salt is generated and sent to the client during registration to prevent dictionary attacks.
2. **Peppering:** A random pepper is generated on the server side and used to further hash the password.
3. **PRF-Based 2FA:** A pseudorandom function (PRF) is used to generate a unique token for two-factor authentication.

This approach mitigates the risks associated with common password authentication methods, including database compromise and offline brute-force attacks.

### Pseudorandom Fuctions and 2FA

A pseudorandom function (PRF) is used to generate unpredictable values based on a shared secret. These functions provide a deterministic yet unpredictable output, which is ideal for generating 2FA tokens. The server and client can both generate the same PRF-based tokens to validate user login attempts.

### Overall System Architecture

The overall system works as follows:

- **One-Sided Authenticated Key Exchange:** A user must register or log in to obtain a certificate from the server. This certificate is used for subsequent communication.
- **Registration:** A new user creates an account by providing their password and undergoing a cryptographic process involving hashing, salting, and 2FA verification.
- **Login:** An existing user can log in by proving their knowledge of the password and successfully completing 2FA.
- **Two-Sided Authenticated Key Exchange:** After registration or login, users can securely communicate with each other using a key exchange protocol based on RSA and Diffie-Hellman.

## Key Concepts

### One-Sided Authenticated Key Exchange

The one-sided authenticated key exchange ensures that a user can authenticate with the server to retrieve their certificate. This process involves Diffie-Hellman key exchange, where the client generates a public key (A) and the server generates its own (B). Both values are exchanged, and the server signs the exchange with its secret key to prove authenticity.

<img width="500" alt="Screenshot 2024-12-21 at 12 12 16 AM" src="https://github.com/user-attachments/assets/3523ac7c-a00b-4758-bbb1-862f8115ca81" />

From this point on, all communication is encrypted under authenticated encryption.

### Registration

During registration, the client provides a unique user identifier (ID) and a password. The server generates a random salt, which is sent to the client. The client then hashes their password with the salt. The server generates a pepper and hashes the password again. The final hash is stored in the server’s database, along with the salt and a PRF seed used for two-factor authentication.

Here is the full registration protocol:

<img width="590" alt="Screenshot 2024-12-21 at 12 12 50 AM" src="https://github.com/user-attachments/assets/7e6eeb6c-df1e-43c0-a8c1-f0be11046a96" />

### Login

The login process involves the client providing their user ID to the server. The server retrieves the associated salt from the database and sends it back to the client. The client hashes their password with the salt and sends it to the server. The server tries various peppers until it finds a match. Then, the client generates a 2FA response, which is verified by the server.

Here is the full login protocol:

<img width="550" alt="Screenshot 2024-12-21 at 12 13 14 AM" src="https://github.com/user-attachments/assets/0e3cb3f4-bdfe-4b59-b55a-6069ddd17a89" />

### Two-Sided Authenticated Key Exchange

After successful registration or login, the user is able to securely communicate with other users. This step involves mutual authentication and key exchange between two users. Each user verifies the other’s certificate, and Diffie-Hellman key exchange is used to generate a shared secret for secure communication.

Here is the two-sided authenticated key exchange protocol:

<img width="592" alt="Screenshot 2024-12-21 at 12 13 54 AM" src="https://github.com/user-attachments/assets/aff4c3cf-71eb-4e57-941a-1a22083c3053" />

After key exchange, all communication can be encrypted.

## Usage

### Running the Server
1. **Install Dependencies:** Ensure you have Go installed. Run go mod tidy to install any dependencies.
2. **Start the Server:** Run go run auth_server.go to start the server. By default, the server will listen on port 8080.
3. **Server Configuration:** Modify server/config.yaml to customize the server’s behavior.

## How It Works

### Registration Flow

1. The client connects to the server and provides a unique user ID.
2. The server generates a random salt and sends it to the client.
3. The client hashes their password with the salt and sends it to the server.
4. The server generates a pepper, hashes the password again, and stores the resulting hash along with the salt in the database.
5. The server sends a PRF seed to the client to be used in 2FA.
6. The client generates a 2FA response based on the PRF seed and sends it to the server.
7. The server verifies the 2FA response and proceeds to generate the user’s certificate.
8. The server sends the certificate to the client, completing the registration process.

### Login Flow

1. The client provides their user ID.
2. The server retrieves the associated salt and sends it to the client.
3. The client hashes their password with the salt and sends it back to the server.
4. The server tries various peppers to find a match.
5. The client generates a 2FA response based on the PRF seed and sends it to the server.
6. The server verifies the 2FA response and proceeds to generate a certificate.
7. The certificate is sent to the client, completing the login process.

### Key Exchange and Communication

After registration or login, the client and server perform a Diffie-Hellman key exchange to generate a shared secret. This shared secret is used to encrypt all subsequent communication between the client and the server, ensuring confidentiality and authenticity.

## Security Considerations

- **Password Protection:** The password is never stored in plaintext and is protected through salting, peppering, and hashing.
- **2FA:** The system uses a pseudorandom function (PRF) for time-based 2FA, which adds an additional layer of security.
- **Public Key Infrastructure:** Digital signatures ensure the authenticity of certificates, preventing impersonation attacks.
- **Secure Communication:** All communication after key exchange is encrypted using symmetric-key authenticated encryption.
