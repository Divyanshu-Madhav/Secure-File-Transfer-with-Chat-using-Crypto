#include <iostream>
#include <fstream>
#include <cryptlib.h>
#include <osrng.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <hex.h>
#include <files.h>
#include <rsa.h>
#include <base64.h>
#include <dsa.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h> // Include this header for close

using namespace CryptoPP;
using namespace std;

const string FILE_TO_SEND = "file_to_send.txt";
const int PORT = 12345;

// Function to encrypt the file with AES
void EncryptFile(const SecByteBlock &key, const string &infile, const string &outfile) {
    CBC_Mode<AES>::Encryption aesEncryption(key, key.size());
    FileSource fs(infile.c_str(), true,
        new StreamTransformationFilter(aesEncryption,
            new FileSink(outfile.c_str())
        )
    );
}

// Function to encrypt AES key with RSA public key
string EncryptAESKey(SecByteBlock &aesKey, RSA::PublicKey &rsaPublicKey) {
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Encryptor encryptor(rsaPublicKey);

    string encryptedAESKey;
    StringSource ss(aesKey, aesKey.size(), true,
        new PK_EncryptorFilter(rng, encryptor, new Base64Encoder(new StringSink(encryptedAESKey)))
    );

    return encryptedAESKey;
}

// Function to sign a message with DSA
string SignMessage(const string &message, DSA::PrivateKey &dsaPrivateKey) {
    AutoSeededRandomPool rng;
    DSA::Signer signer(dsaPrivateKey);

    byte digest[SHA256::DIGESTSIZE];
    SHA256().CalculateDigest(digest, (const byte*)message.data(), message.size());

    SecByteBlock signature(signer.SignatureLength());
    signer.SignMessage(rng, digest, sizeof(digest), signature);

    return string((char*)signature.data(), signature.size());
}

// Client communication
void startClient() {
    // Create client socket
    int clientSock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_port = htons(PORT);
    connect(clientSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

    // Generate AES key
    AutoSeededRandomPool rng;
    SecByteBlock aesKey(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(aesKey, aesKey.size());

    // Load RSA public key of the server
    RSA::PublicKey rsaPublicKey;
    FileSource rsaFile("../keys/server_rsa_public.pem", true);
    rsaPublicKey.Load(rsaFile); // Directly loading without HexDecoder or PEM_Load

    // Encrypt AES key with RSA public key
    string encryptedAESKey = EncryptAESKey(aesKey, rsaPublicKey);

    // Send encrypted AES key
    send(clientSock, encryptedAESKey.c_str(), encryptedAESKey.size(), 0);

    // Encrypt the file with AES
    EncryptFile(aesKey, FILE_TO_SEND, "file_encrypted.txt");

    // Send the encrypted file
    ifstream infile("file_encrypted.txt", ios::binary);
    string fileData((istreambuf_iterator<char>(infile)), istreambuf_iterator<char>());
    send(clientSock, fileData.c_str(), fileData.size(), 0);

    // Load DSA private key for signing
    DSA::PrivateKey dsaPrivateKey;
    FileSource dsaFile("../keys/server_dsa_private.pem", true);
    dsaPrivateKey.Load(dsaFile); // Directly loading without HexDecoder or PEM_Load

    // Sign the encrypted file data
    string signature = SignMessage(fileData, dsaPrivateKey);
    send(clientSock, signature.c_str(), signature.size(), 0);

    close(clientSock);
}

int main() {
    startClient();
    return 0;
}
