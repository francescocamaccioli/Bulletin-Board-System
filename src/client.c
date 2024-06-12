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

#define BUF_SIZE 4096
#define SURN_MAX_LEN 1024
#define DATE_LEN 30
#define SELECT_SIZE 128

int login(int lissoc){
    printf("insert username: \n");
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

    int ret, lissoc;
    uint8_t dim;
    struct sockaddr_in srv_addr;
    char buffer [BUF_SIZE];
    uint16_t port = (uint16_t)strtol(argv[1], NULL, 10);
    lissoc= socket(AF_INET, SOCK_STREAM, 0);
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family=AF_INET;
    srv_addr.sin_port=htons(port);
    inet_pton(AF_INET, "127.0.0.1", &srv_addr.sin_addr);
    ret = connect(lissoc, (struct sockaddr*) &srv_addr, sizeof(srv_addr));
    if (ret < 0){
        perror("Errore nella connect \n");
        exit(-1);
    }

    ret = send(lissoc, (void*)"HELLO\0", 6, 0);
    if (ret < 0){
        perror("error sending HELLO");
        exit(-1);
    }

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
    printf("\n");
    // deserialize certificate using d2i_X509
    server_cert = d2i_X509(NULL, (const unsigned char**)&cert_buffer, cert_len_long);
    if (!server_cert){
        perror("error deserializing server certificate");
        exit(-1);
    }
    // extracting RSA public key from certificate
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

    // receive the server IV
    unsigned char iv [16];
    memset(iv, 0, 16);
    ret = recv(lissoc, (void*)iv, 16, 0);
    if (ret < 0){
        perror("error receiving IV");
        exit(-1);
    }
    printf("IV: \n");
    for (int i = 0; i < 16; i++){
        printf("%02x", iv[i]);
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
    // decrypting the nonce
    EVP_CIPHER_CTX* ctx_decrypt;
    ctx_decrypt = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx_decrypt);
    EVP_DecryptInit(ctx_decrypt, EVP_aes_256_cbc(), AES_256_key, iv);
    unsigned char* decrypted_nonce;
    decrypted_nonce = (unsigned char*)malloc(nonce_len);
    int decrypted_len;
    int outlen;
    EVP_DecryptUpdate(ctx_decrypt, decrypted_nonce, &outlen, nonce, nonce_len);
    decrypted_len = outlen;
    int res = EVP_DecryptFinal(ctx_decrypt, decrypted_nonce + decrypted_len, &outlen);
    if (res == 0 ){
        perror("error decrypting nonce");
        exit(-1);
    }
    decrypted_len += outlen;
    EVP_CIPHER_CTX_free(ctx_decrypt);
    printf("\n Decrypted Nonce: \n");
    for (int i = 0; i < decrypted_len; i++){
        printf("%02x", decrypted_nonce[i]);
    }
    printf("\n");
    int decrypted_nonce_len = decrypted_len;
    // reverse the nonce
    for (int i = 0; i < decrypted_nonce_len/2; i++){
        unsigned char temp = decrypted_nonce[i];
        decrypted_nonce[i] = decrypted_nonce[decrypted_nonce_len - i - 1];
        decrypted_nonce[decrypted_nonce_len - i - 1] = temp;
    }


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
    
    // send the HMAC to the server
    ret = send(lissoc, (void*)hmac, hmac_len, 0);
    if (ret < 0){
        perror("error sending HMAC");
        exit(-1);
    }
    





    close(lissoc);
    return 0;
}