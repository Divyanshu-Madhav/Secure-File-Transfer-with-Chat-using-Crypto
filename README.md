# Secure File Transfer with Chat using Crypto++

This project implements a secure file transfer system that uses AES encryption for file data and RSA/DSA for key exchange and signing. It consists of a client-server architecture where the client sends encrypted files to the server.

## Prerequisites

- C++ compiler
- CMake
- OpenSSL
- Crypto++ library

### Install Crypto++

If you haven't installed the Crypto++ library, you can do so on Ubuntu with the following command:
sudo apt-get install libcryptopp-dev



## Build Instructions

1. Create a build directory and compile the project:
mkdir build
cd build
cmake ..
make

## Usage

1. Ensure the `keys` directory contains the RSA and DSA keys:
   - `server_rsa_private.pem`
   - `server_rsa_public.pem`
   - `client_rsa_private.pem`
   - `client_rsa_public.pem`
   - `server_dsa_private.pem`
   - `server_dsa_public.pem`

2. To run the server, open a terminal and execute:
./server

3. In another terminal, run the client:
./client

## Key Generation

To generate the necessary RSA and DSA keys, use the following commands:

### Generate RSA Keys

# Generate RSA private key
openssl genpkey -algorithm RSA -out keys/server_rsa_private.pem

# Generate RSA public key
openssl rsa -pubout -in keys/server_rsa_private.pem -out keys/server_rsa_public.pem

### Generate DSA Keys

# Generate DSA private key
openssl dsaparam -out keys/server_dsa_param.pem 2048
openssl gendsa -out keys/server_dsa_private.pem keys/server_dsa_param.pem

# Generate DSA public key
openssl dsa -pubout -in keys/server_dsa_private.pem -out keys/server_dsa_public.pem



## Project Description

The **Secure File Transfer with Chat** project provides a robust solution for securely transferring files between a client and a server. By leveraging advanced cryptographic techniques such as RSA, DSA, and AES, this application ensures that data remains confidential and tamper-proof during transmission.

### Key Features

- **AES Encryption**: The project employs AES (Advanced Encryption Standard) for encrypting files before transmission, ensuring that the contents remain private and secure.
  
- **RSA Encryption**: The AES keys are securely transmitted using RSA (Rivest-Shamir-Adleman) public key encryption, allowing the client and server to exchange keys without exposing them to potential eavesdroppers.
  
- **DSA Signing**: Digital Signature Algorithm (DSA) is used for signing the transmitted files. This guarantees the integrity and authenticity of the files, allowing the recipient to verify that they have not been altered during transmission.

- **Socket Communication**: The application utilizes TCP sockets for reliable communication between the client and server, facilitating the secure exchange of files and signatures.

### Use Cases

This project is suitable for scenarios where secure file transfer is critical, such as:

- **Corporate Data Transfers**: Sending sensitive documents within a company or between business partners.
- **Personal File Sharing**: Sharing private files with friends or family in a secure manner.
- **Secure Backup Solutions**: Safeguarding important files by transferring them to a secure server.

By implementing this project, users can ensure that their data is protected against unauthorized access and tampering during transit.
# Secure-File-Transfer-with-Chat-using-Crypto
