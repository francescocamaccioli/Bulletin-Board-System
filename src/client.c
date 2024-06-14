#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include "utils.h"

// function to receive IV and HMAC and check if they are correct
int receiveIVHMAC(int lissoc, unsigned char* iv, unsigned char* shared_secret, size_t shared_secret_len){
    // receive the IV
    int ret = recv(lissoc, (void*)iv, 16, 0);
    if (ret < 0){
        perror("error receiving IV");
        return -1;
    }
    // print the received IV
    printf("Received IV: \n");
    for (int i = 0; i < 16; i++){
        printf("%02x", iv[i]);
    }
    // receive the IV HMAC
    uint32_t iv_hmac_len_n;
    ret = recv(lissoc, (void*)&iv_hmac_len_n, sizeof(uint32_t), 0);
    if (ret < 0){
        perror("error receiving IV HMAC length");
        return -1;
    }
    long iv_hmac_len = ntohl(iv_hmac_len_n);
    printf("iv_hmac_len: %d\n", iv_hmac_len);
    unsigned char* iv_hmac = malloc(iv_hmac_len);
    ret = recv(lissoc, (void*)iv_hmac, iv_hmac_len, 0);
    if (ret < 0){
        perror("error receiving IV HMAC");
        return -1;
    }
    // print the received HMAC
    printf("Received IV HMAC: \n");
    for (int i = 0; i < iv_hmac_len; i++){
        printf("%02x", iv_hmac[i]);
    }
    printf("\n");


    // compute the HMAC of the IV
    HMAC_CTX* iv_hmac_ctx;
    iv_hmac_ctx = HMAC_CTX_new();
    HMAC_Init(iv_hmac_ctx, shared_secret, shared_secret_len, EVP_sha256());
    HMAC_Update(iv_hmac_ctx, iv, 16);
    unsigned char* iv_hmac_comp;
    unsigned int iv_hmac_len_comp;
    iv_hmac_comp = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    HMAC_Final(iv_hmac_ctx, iv_hmac_comp, &iv_hmac_len_comp);
    HMAC_CTX_free(iv_hmac_ctx);
    // print the computed HMAC
    printf("Computed IV HMAC: \n");
    for (int i = 0; i < iv_hmac_len_comp; i++){
        printf("%02x", iv_hmac_comp[i]);
    }
    // check if the HMACs are equal
    if (memcmp(iv_hmac, iv_hmac_comp, iv_hmac_len) != 0){
        puts("IV HMACs are different, aborting");
        return -1;
    }
    else{
        puts("IV HMACs are equal, parameters accepted");
    }
    return 0;
}

// decrypt a message using AES 256 CBC
void decrypt_message(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext, int* plaintext_len){
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, iv);
    int outlen;
    EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, ciphertext_len);
    *plaintext_len = outlen;
    EVP_DecryptFinal(ctx, plaintext + outlen, &outlen);
    *plaintext_len += outlen;
    EVP_CIPHER_CTX_free(ctx);
}



void help(){
    puts("┌───────────────────────────────────────────────────────┐");
    puts("│ Welcome to Bulletin Board System!                     │");
    puts("│                                                       │");
    puts("│ Available commands:                                   │");
    puts("│ register <email> <username> <password>                │");
    puts("│ login <username> <password>                           │");
    puts("│ logout                                                │");
    puts("│ list <n>             (to print latest n messages)     │");
    puts("│ get <mid>            (to download a message content)  │");
    puts("│ add <title> <body>   (to add a message to BBS)        │");
    puts("└───────────────────────────────────────────────────────┘");
}

int lissoc = 0;

void handle_sig(int sig) {
    printf("\nCaught signal %d, closing socket and exiting...\n", sig);
    if (lissoc > 0) {
        close(lissoc);
    }
    exit(0);
}

int login(int lissoc){
    char username [BUF_SIZE];
    scanf("%s", username);
    int size = strlen(username);
    uint8_t dim = htons(size);
    printf("username: %s\n", username);
    int ret = send(lissoc, (void*)&size, sizeof(uint8_t), 0);
    if (ret < 0){
        perror("error sending username length");
        exit(-1);
    }
    ret = send(lissoc, (void*)username, size, 0);
    if (ret < 0){
        perror("error sending username");
        exit(-1);
    }
    return 0;
}

int main(int argc, char* argv[]){

    if (argc != 2) {
        fprintf(stderr, "Invalid arguments!\nUsage: ./client <port>\n");
        exit(-1);
    }

    signal(SIGINT, handle_sig);
    signal(SIGQUIT, handle_sig);
    
    int ret;
    uint8_t dim;
    struct sockaddr_in srv_addr;
    char buffer [BUF_SIZE];
    uint16_t port = (uint16_t)strtol(argv[1], NULL, 10);
    lissoc = socket(AF_INET, SOCK_STREAM, 0);
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family=AF_INET;
    srv_addr.sin_port=htons(port);
    inet_pton(AF_INET, "127.0.0.1", &srv_addr.sin_addr);
    ret = connect(lissoc, (struct sockaddr*) &srv_addr, sizeof(srv_addr));
    if (ret < 0){
        perror("Server socket connection error\n");
        exit(-1);
    }

    puts("Starting Handshake...");
    puts("Sending hello to server");
    ret = send(lissoc, (void*)"HELLO\0", 6, 0);
    if (ret < 0){
        perror("error sending HELLO");
        exit(-1);
    }

    puts("Receiving certificate from server");
    // receiving server certificate from socket
    X509* server_cert;
    uint32_t cert_len;
    ret = recv(lissoc, (void*)&cert_len, sizeof(uint32_t), 0);
    if (ret < 0){
        perror("error receiving server certificate length");
        exit(-1);
    }
    long cert_len_long = ntohl(cert_len);
    printf("cert_len: %d\n", cert_len_long);
    unsigned char* cert_buffer = (unsigned char*)malloc(cert_len_long);
    ret = recv(lissoc, (void*)cert_buffer, cert_len_long, 0);
    if (ret < 0){
        perror("error receiving server certificate");
        exit(-1);
    }
    // printing serialized certificate
    printf("Serialized certificate: \n");
    for (int i = 0; i < cert_len_long; i++){
        printf("%02x", cert_buffer[i]);
    }
    printf("\n\n");
    // deserialize certificate using d2i_X509
    server_cert = d2i_X509(NULL, (const unsigned char**)&cert_buffer, cert_len_long);
    if (!server_cert){
        perror("error deserializing server certificate");
        exit(-1);
    }
    // extracting RSA public key from certificate
    puts("Extracting RSA public key from certificate");
    EVP_PKEY* server_pubkey = X509_get_pubkey(server_cert);
    if (!server_pubkey){
        perror("error extracting public key from certificate");
        exit(-1);
    }
    // printing public key information
    RSA* rsa_pubkey = EVP_PKEY_get1_RSA(server_pubkey);
    if (!rsa_pubkey){
        perror("error extracting RSA public key");
        exit(-1);
    }
    printf("RSA public key: \n");
    printf("Modulus: %s\n", BN_bn2hex(RSA_get0_n(rsa_pubkey)));
    printf("Exponent: %s\n", BN_bn2hex(RSA_get0_e(rsa_pubkey)));
    RSA_free(rsa_pubkey);

    // at the moment we assume that the certificate is valid hence it's self signed
    // we don't request the client to send its certificate for simplicity

    // generate DH parameters using RFC 5114: p and g are fixed
    EVP_PKEY* dh_params;
    dh_params = EVP_PKEY_new();
    EVP_PKEY_set1_DH(dh_params, DH_get_2048_224());

    // generating the client public-private key pair
    EVP_PKEY_CTX* pkDHctx = EVP_PKEY_CTX_new(dh_params, NULL);
    if (!pkDHctx){
        perror("Failed to create EVP_PKEY_CTX");
        EVP_PKEY_free(dh_params);
        return 1;
    }
    EVP_PKEY* client_keypair = NULL;
    ret = EVP_PKEY_keygen_init(pkDHctx);
    if (ret <= 0){
        perror("Failed to initialize key generation");
        EVP_PKEY_CTX_free(pkDHctx);
        EVP_PKEY_free(dh_params);
        return 1;
    }
    ret = EVP_PKEY_keygen(pkDHctx, &client_keypair);
    if (ret <= 0){
        perror("Failed to generate key pair");
        EVP_PKEY_CTX_free(pkDHctx);
        EVP_PKEY_free(dh_params);
        return 1;
    }

    // Extract the DH structure from the EVP_PKEY structure
    DH* dh = EVP_PKEY_get1_DH(client_keypair);
    if (!dh) {
        perror("Failed to extract DH structure from key pair");
        EVP_PKEY_free(client_keypair);
        EVP_PKEY_CTX_free(pkDHctx);
        EVP_PKEY_free(dh_params);
        return 1;
    }

    // Extract the public key from the DH structure
    const BIGNUM* pub_key_bn;
    const BIGNUM* priv_key_bn;
    DH_get0_key(dh, &pub_key_bn, &priv_key_bn); // Second argument is for the private key

    // Convert the public key from BIGNUM to string
    char* pub_key_str = BN_bn2hex(pub_key_bn);
    if (!pub_key_str) {
        perror("Failed to convert public key to string");
        DH_free(dh);
        EVP_PKEY_free(client_keypair);
        EVP_PKEY_CTX_free(pkDHctx);
        EVP_PKEY_free(dh_params);
        return 1;
    }

    // Print or use the public key string as needed
    // Serialize the public key
    unsigned char* pub_key_buf = NULL;
    int pub_key_len = i2d_PUBKEY(client_keypair, &pub_key_buf);
    if (pub_key_len < 0) {
        perror("Failed to serialize public key");
        DH_free(dh);
        EVP_PKEY_free(client_keypair);
        EVP_PKEY_CTX_free(pkDHctx);
        EVP_PKEY_free(dh_params);
        return 1;
    }

    // print the serialized public key
    printf("Serialized public key: \n");
    for (int i = 0; i < pub_key_len; i++){
        printf("%02x", pub_key_buf[i]);
    }
    printf("\n");

    // Send the length of the serialized public key buffer
    uint32_t pub_key_len_n = htonl(pub_key_len);
    ret = send(lissoc, (void*)&pub_key_len_n, sizeof(uint32_t), 0);
    if (ret < 0) {
        perror("Error sending public key length");
        DH_free(dh);
        EVP_PKEY_free(client_keypair);
        EVP_PKEY_CTX_free(pkDHctx);
        EVP_PKEY_free(dh_params);
        free(pub_key_buf);
        return 1;
    }

    // Send the serialized public key to the server
    ret = send(lissoc, (void*)pub_key_buf, pub_key_len, 0);
    if (ret < 0) {
        perror("Error sending public key");
        DH_free(dh);
        EVP_PKEY_free(client_keypair);
        EVP_PKEY_CTX_free(pkDHctx);
        EVP_PKEY_free(dh_params);
        free(pub_key_buf);
        return 1;
    }

    // Receive the server's public key
    uint32_t server_pub_key_len_n;
    ret = recv(lissoc, (void*)&server_pub_key_len_n, sizeof(uint32_t), 0);
    if (ret < 0) {
        perror("Error receiving server public key length");
        DH_free(dh);
        EVP_PKEY_free(client_keypair);
        EVP_PKEY_CTX_free(pkDHctx);
        EVP_PKEY_free(dh_params);
        free(pub_key_buf);
        return 1;
    }
    uint32_t server_pub_key_len = ntohl(server_pub_key_len_n);
    unsigned char* server_pub_key_buf = (unsigned char*)malloc(server_pub_key_len);
    ret = recv(lissoc, (void*)server_pub_key_buf, server_pub_key_len, 0);
    if (ret < 0) {
        perror("Error receiving server public key");
        DH_free(dh);
        EVP_PKEY_free(client_keypair);
        EVP_PKEY_CTX_free(pkDHctx);
        EVP_PKEY_free(dh_params);
        free(pub_key_buf);
        free(server_pub_key_buf);
        return 1;
    }

    printf("server public key length received\n");
    fflush(stdout);

    // receive digital signature on server public key
    uint32_t sign_len;
    ret = recv(lissoc, (void*)&sign_len, sizeof(uint32_t), 0);
    if (ret < 0){
        perror("error receiving signature length");
        exit(-1);
    }
    long sign_len_n = ntohl(sign_len);
    unsigned char* pksign = (unsigned char*)malloc(sign_len_n);
    ret = recv(lissoc, (void*)pksign, sign_len_n, 0);
    if (ret < 0){
        perror("error receiving signature");
        exit(-1);
    }
    // verify the signature
    EVP_MD_CTX* ctx_verify;
    ctx_verify = EVP_MD_CTX_new();
    EVP_VerifyInit(ctx_verify, EVP_sha256());
    EVP_VerifyUpdate(ctx_verify, server_pub_key_buf, server_pub_key_len);
    int verify = EVP_VerifyFinal(ctx_verify, pksign, sign_len_n, server_pubkey);
    if (verify != 1){
        perror("error verifying signature");
        exit(-1);
    }
    else{
        printf("signature verified, parameters accepted\n");
    }
    EVP_MD_CTX_free(ctx_verify);


    // Deserialize the server's public key
    EVP_PKEY* server_pub_key = d2i_PUBKEY(NULL, (const unsigned char**)&server_pub_key_buf, server_pub_key_len);
    if (!server_pub_key) {
        perror("Error deserializing server public key");
        DH_free(dh);
        EVP_PKEY_free(client_keypair);
        EVP_PKEY_CTX_free(pkDHctx);
        EVP_PKEY_free(dh_params);
        free(pub_key_buf);
        free(server_pub_key_buf);
        return 1;
    }

    printf("public key length received\n");
    fflush(stdout);

    // Generate the shared secret
    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(client_keypair, NULL);
    EVP_PKEY_derive_init(ctx_drv);
    EVP_PKEY_derive_set_peer(ctx_drv, server_pub_key);
    unsigned char* shared_secret;

    size_t shared_secret_len;
    EVP_PKEY_derive(ctx_drv, NULL, &shared_secret_len);

    shared_secret = (unsigned char*)malloc(shared_secret_len);
    EVP_PKEY_derive(ctx_drv, shared_secret, &shared_secret_len);


    // Print the shared secret
    printf("Shared secret: \n");
    for (int i = 0; i < shared_secret_len; i++) {
        printf("%02x", shared_secret[i]);
    }
    printf("\n");

    // hashing the shared secret to obtain the AES 256 key
    unsigned char* AES_256_key;
    int AES_256_key_len;
    EVP_MD_CTX* keyctx;
    AES_256_key = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    keyctx = EVP_MD_CTX_new();
    EVP_DigestInit(keyctx, EVP_sha256());
    EVP_DigestUpdate(keyctx,(unsigned char*)shared_secret, shared_secret_len);
    EVP_DigestFinal(keyctx, AES_256_key, (unsigned int*)&AES_256_key_len);
    EVP_MD_CTX_free(keyctx);

    printf("AES 256 key: \n");
    for (int i = 0; i < AES_256_key_len; i++){
        printf("%02x", AES_256_key[i]);
    }

    unsigned char* srv_iv = malloc(16);
    receiveIVHMAC(lissoc, srv_iv, shared_secret, shared_secret_len);
    printf("srv_iv: \n");
    for (int i = 0; i < 16; i++){
        printf("%02x", srv_iv[i]);
    }
    
    // receiving encrypted nonce length
    uint32_t nonce_len_n;
    ret = recv(lissoc, (void*)&nonce_len_n, sizeof(uint32_t), 0);
    if (ret < 0){
        perror("error receiving nonce length");
        exit(-1);
    }
    long nonce_len = ntohl(nonce_len_n);
    unsigned char* nonce = (unsigned char*)malloc(nonce_len);
    // receiving encrypted nonce
    ret = recv(lissoc, (void*)nonce, nonce_len, 0);
    if (ret < 0){
        perror("error receiving nonce");
        exit(-1);
    }
    printf("\n Encrypted Nonce: \n");
    for (int i = 0; i < nonce_len; i++){
        printf("%02x", nonce[i]);
    }
    printf("\n");
    // decrypting the nonce using the decryption funciton
    unsigned char decrypted_nonce[nonce_len];
    int decrypted_nonce_len;
    decrypt_message(nonce, nonce_len, AES_256_key, srv_iv, decrypted_nonce, &decrypted_nonce_len);
    // print the decrypted nonce
    printf("\n Decrypted Nonce: \n");
    for (int i = 0; i < decrypted_nonce_len; i++){
        printf("%02x", decrypted_nonce[i]);
    }
    printf("\n");
    for (int i = 0; i < decrypted_nonce_len/2; i++){
        unsigned char temp = decrypted_nonce[i];
        decrypted_nonce[i] = decrypted_nonce[decrypted_nonce_len - i - 1];
        decrypted_nonce[decrypted_nonce_len - i - 1] = temp;
    }

    printf("\n Reversed Nonce: \n");
    for (int i = 0; i < decrypted_nonce_len; i++){
        printf("%02x", decrypted_nonce[i]);
    }
    printf("\n");

    // computing the HMAC of the nonce
    HMAC_CTX* hmac_ctx;
    hmac_ctx = HMAC_CTX_new();

    HMAC_Init(hmac_ctx, shared_secret, shared_secret_len, EVP_sha256());
    HMAC_Update(hmac_ctx, decrypted_nonce, decrypted_nonce_len);
    unsigned char* hmac;
    unsigned int hmac_len;
    hmac = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    HMAC_Final(hmac_ctx, hmac, &hmac_len);
    HMAC_CTX_free(hmac_ctx);

    // print the HMAC
    printf("\n");
    printf("HMAC: ");
    for (int i = 0; i < hmac_len; i++){
        printf("%02x", hmac[i]);
    }
    printf("\n");
    
    // build a structure to send the HMAC and the timestamp
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char timestamp[DATE_LEN];
    // timestamp format: YYYY-MM-DD HH:MM:SS
    sprintf(timestamp, "%d-%02d-%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    uint32_t timestamp_len = htonl(DATE_LEN);
    struct srvsend{
        char timestamp[DATE_LEN];
        unsigned char hmac[EVP_MAX_MD_SIZE];
    };
    struct srvsend tosend;
    memcpy(tosend.timestamp, timestamp, DATE_LEN);
    memcpy(tosend.hmac, hmac, hmac_len);
    // generate the IV for AES encryption
    unsigned char iv2 [16];
    RAND_bytes(iv2, 16);

    // print the IV 
    printf("IV2: \n");
    for (int i = 0; i < 16; i++){
        printf("%02x", iv2[i]);
    }
    printf("\n");

    // encrypt the structure
    EVP_CIPHER_CTX* ctx_encrypt;
    ctx_encrypt = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx_encrypt);
    unsigned char* encrypted_struct;
    int encrypted_len;
    int outlen2;
    long struct_len = DATE_LEN + hmac_len;
    encrypted_struct = (unsigned char*)malloc(struct_len);
    EVP_EncryptInit(ctx_encrypt, EVP_aes_256_cbc(), AES_256_key, iv2);
    EVP_EncryptUpdate(ctx_encrypt, encrypted_struct, &outlen2, (unsigned char*)&tosend, struct_len);
    encrypted_len = outlen2;
    int res2 = EVP_EncryptFinal(ctx_encrypt, encrypted_struct + encrypted_len, &outlen2);
    if (res2 == 0){
        perror("error encrypting structure");
        exit(-1);
    }
    encrypted_len += outlen2;
    
    // print the encrypted structure
    printf("Encrypted structure: \n");
    for (int i = 0; i < encrypted_len; i++){
        printf("%02x", encrypted_struct[i]);
    }
    printf("\n");

    // send the IV
    ret = send(lissoc, (void*)iv2, 16, 0);
    if (ret < 0){
        perror("error sending IV");
        exit(-1);
    }
    // send the encrypted structure
    uint32_t encrypted_len_n = htonl(encrypted_len);
    ret = send(lissoc, (void*)&encrypted_len_n, sizeof(uint32_t), 0);
    if (ret < 0){
        perror("error sending encrypted structure length");
        exit(-1);
    }
    puts("encrypted_len sent");
    ret = send(lissoc, (void*)encrypted_struct, encrypted_len, 0);
    if (ret < 0){
        perror("error sending encrypted structure");
        exit(-1);
    }
    puts("Handshake successfully completed!");
    

    char input[BUF_SIZE];
    help();
    // main command parsing loop
    while (1) {
        printf("Enter command: \n> ");
        if (fgets(input, BUF_SIZE, stdin) == NULL) {
            perror("Error reading input");
            continue;
        }
        // Remove newline character
        input[strcspn(input, "\n")] = 0;

        char* command = strtok(input, " ");
        char* arg = strtok(NULL, " ");

        if (command == NULL) {
            printf("Invalid input, please try again.\n");
            continue;
        }

        if (strcmp(input, "register") == 0) {
            if (arg == NULL) {
                printf("Username and password are required to register.\n");
            } 
            else{
                char* username = arg;
                char* password = strtok(NULL, " ");
            }
        } else if (strcmp(input, "login") == 0) {
            puts("Logging in...");
            char* username = arg;
        } else if (strcmp(input, "list") == 0) {
            puts("Listing...");
            int n = atoi(arg);
            // checking overflows
            if(n < 0){
                puts("Invalid n, try again");
                continue;
            }
            
        } else if (strcmp(input, "get") == 0) {
            puts("Downloading...");
            int mid = atoi(arg);
            if(mid < 0){
                puts("Invalid mid, try again");
                continue;
            }
            printf("mid=%d\n",mid);
        } else if (strcmp(input, "add") == 0) {
            puts("Posting message...");
        } else if (strcmp(input, "logout") == 0) {
            printf("Logging out...\n");
            break;
        } else if (strcmp(input, "help") == 0) {
            help();
        } else {
            printf("Invalid choice, please try again.\n");
        }
    }
    

    if(writen(lissoc, (void*)"logout", 7) < 0){
        perror("error sending logout request");
        exit(-1);
    }
    close(lissoc);

    return 0;
}
