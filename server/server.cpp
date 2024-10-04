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
#include <unistd.h>  // Include this header for close

using namespace CryptoPP;
using namespace std;

const int PORT = 12345;

// Function to decrypt AES key with RSA private key
SecByteBlock DecryptAESKey(const string &encryptedAESKey, RSA::PrivateKey &rsaPrivateKey) {
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Decryptor decryptor(rsaPrivateKey);

    SecByteBlock aesKey(AES::DEFAULT_KEYLENGTH);
    StringSource(encryptedAESKey, true, new Base64Decoder(
        new PK_DecryptorFilter(rng, decryptor, new ArraySink(aesKey, aesKey.size()))
    ));

    return aesKey;
}

// Function to decrypt the file with AES
void DecryptFile(const SecByteBlock &key, const string &infile, const string &outfile) {
    CBC_Mode<AES>::Decryption aesDecryption(key, key.size());
    FileSource fs(infile.c_str(), true,
        new StreamTransformationFilter(aesDecryption,
            new FileSink(outfile.c_str())
        )
    );
}

// Function to verify DSA signature
bool VerifySignature(const string &message, const string &signature, DSA::PublicKey &dsaPublicKey) {
    DSA::Verifier verifier(dsaPublicKey);
    byte digest[SHA256::DIGESTSIZE];
    SHA256().CalculateDigest(digest, (const byte*)message.data(), message.size());
    return verifier.VerifyMessage(digest, sizeof(digest), (const byte*)signature.data(), signature.size());
}

// Server communication
void startServer() {
    // Create server socket
    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);
    bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(serverSock, 1);
    
    cout << "Waiting for client connection..." << endl;
    int clientSock = accept(serverSock, nullptr, nullptr);
    cout << "Client connected!" << endl;

    // Load RSA private key
    RSA::PrivateKey rsaPrivateKey;
    FileSource rsaFile("../keys/server_rsa_private.pem", true);
    rsaPrivateKey.Load(rsaFile);

    // Load DSA public key
    DSA::PublicKey dsaPublicKey;
    FileSource dsaFile("../keys/server_dsa_public.pem", true);
    dsaPublicKey.Load(dsaFile);

    // Receive and decrypt AES key
    string encryptedAESKey;
    char buffer[1024];
    recv(clientSock, buffer, sizeof(buffer), 0);
    encryptedAESKey = buffer;
    SecByteBlock aesKey = DecryptAESKey(encryptedAESKey, rsaPrivateKey);

    // Receive and save encrypted file
    string encryptedFileData;
    recv(clientSock, buffer, sizeof(buffer), 0);
    encryptedFileData = buffer;

    ofstream outfile("received_file_encrypted.txt");
    outfile << encryptedFileData;
    outfile.close();

    // Decrypt the file
    DecryptFile(aesKey, "received_file_encrypted.txt", "received_file_decrypted.txt");
    cout << "File decrypted successfully!" << endl;

    // Receive and verify DSA signature
    string signature;
    recv(clientSock, buffer, sizeof(buffer), 0);
    signature = buffer;

    if (VerifySignature(encryptedFileData, signature, dsaPublicKey)) {
        cout << "Signature verified successfully!" << endl;
    } else {
        cout << "Signature verification failed!" << endl;
    }

    close(clientSock);
    close(serverSock);
}

int main() {
    startServer();
    return 0;
}
