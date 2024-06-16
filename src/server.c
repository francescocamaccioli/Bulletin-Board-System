#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "clientlist.h"
#include "utils.h"

int lissoc = 0, connectsoc = 0;

// function to generate an IV and send it together with the HMAC computed with a shared secret
void iv_comm(int selind, unsigned char* iv, unsigned char* shared_secret, int shared_secret_len){
    // generate a random IV
    RAND_poll();
    RAND_bytes(iv, 16);

    // send the IV to the client
    checkreturnint(send(selind, (void*)iv, 16, 0), "error sending IV");
    // print the IV
    printf("IV: ");
    for (int i = 0; i < 16; i++){
        printf("%02x", iv[i]);
    }
    printf("IV sent\n");

    // generate the IV HMAC
    unsigned char* iv_hmac;
    unsigned int iv_hmac_len;
    iv_hmac = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    compute_hmac(iv, 16, shared_secret, shared_secret_len, iv_hmac, &iv_hmac_len);

    printf("IV HMAC: ");
    for (int i = 0; i < iv_hmac_len; i++){
        printf("%02x", iv_hmac[i]);
    }
    printf("\n");

    // send the IV HMAC len to the client
    printf("IV HMAC length: %d\n", iv_hmac_len);
    uint32_t iv_hmac_len_n = htonl(iv_hmac_len);
    checkreturnint(send(selind, (void*)&iv_hmac_len_n, sizeof(uint32_t), 0), "error sending IV HMAC length");
    printf("IV HMAC length sent\n");

    // send the IV HMAC to the client
    checkreturnint(send(selind, (void*)iv_hmac, iv_hmac_len, 0), "error sending IV HMAC");
    printf("IV HMAC sent\n");
}

// function to generate a message signature using the server private key
void sign_message(unsigned char* message, int message_len, unsigned char* signature, unsigned int* signature_len){
    FILE* rsa_priv_key_file = fopen("server_privkey.pem", "r");
    if (!rsa_priv_key_file) {
        perror("Failed to open RSA private key file");
        exit(-1);
    }
    EVP_PKEY* rsa_priv_key = PEM_read_PrivateKey(rsa_priv_key_file, NULL, NULL, "TaylorSwift13");
    if (!rsa_priv_key) {
        perror("Failed to read RSA private key");
        exit(-1);
    }
    fclose(rsa_priv_key_file);

    EVP_MD_CTX* sign_ctx;
    sign_ctx = EVP_MD_CTX_new();
    EVP_SignInit(sign_ctx, EVP_sha256());
    EVP_SignUpdate(sign_ctx, message, message_len);
    EVP_SignFinal(sign_ctx, signature, signature_len, rsa_priv_key);
    EVP_MD_CTX_free(sign_ctx);
}

int main(int argc, char** argv){

    if (argc != 2) {
        fprintf(stderr, "Invalid arguments!\nUsage: ./server <port>\n");
        exit(-1);
    }

    ClientList* clients = createlist();

    FILE *server_cert_file = fopen("server_cert_mykey.pem", "r");
    checkrnull(server_cert_file, "Failed to open server certificate file");
    X509* server_cert;
    server_cert = PEM_read_X509(server_cert_file, NULL, NULL, NULL);
    checkrnull(server_cert, "Failed to read server certificate");
    fclose(server_cert_file);

    //extract public key from server certificate
    EVP_PKEY* server_pub_key = X509_get_pubkey(server_cert);
    checkrnull(server_pub_key, "Failed to extract server public key");

    FILE* rsa_priv_key_file = fopen("server_privkey.pem", "r");
    if (!rsa_priv_key_file) {
        perror("Failed to open RSA private key file");
        return 1;
    }
    EVP_PKEY* rsa_priv_key = PEM_read_PrivateKey(rsa_priv_key_file, NULL, NULL, "TaylorSwift13");
    if (!rsa_priv_key) {
        perror("Failed to read RSA private key");
        return 1;
    }
    fclose(rsa_priv_key_file);

    RSA* rsa = EVP_PKEY_get1_RSA(server_pub_key);
    if (rsa) {
        //printf("RSA Public Key:\n");
        // Print RSA public key components
        //printf("  Modulus: %s\n", BN_bn2hex(RSA_get0_n(rsa)));
        //printf("  Exponent: %s\n", BN_bn2hex(RSA_get0_e(rsa)));
        RSA_free(rsa);
    } else {
        printf("Public key is not an RSA key.\n");
    }

    // Serializing the certificate to send it to the client
    unsigned char *cert_buf = NULL;
    long cert_len = i2d_X509(server_cert, &cert_buf);
    if (cert_len < 0) {
        perror("Failed to serialize server certificate");
        EVP_PKEY_free(server_pub_key);
        X509_free(server_cert);
        return 1;
    }
    
    //now i can send the certificate to the client
    /*
    printf("Serialized certificate length: %d\n", cert_len);
    printf("Serialized certificate:\n");
    for (int i = 0; i < cert_len; i++) {
        printf("%02x", cert_buf[i]);
    }
    printf("\n");
    */
    uint32_t cert_len_n = htonl(cert_len);

    OpenSSL_add_all_algorithms();
    struct sockaddr_in srv_addr, server_addr;
    uint16_t port = (uint16_t)strtol(argv[1], NULL, 10);

    fd_set master;
    fd_set copy; //fd set utilizzato dalla select così non modifico il master
    FD_ZERO(&master);
    FD_ZERO(&copy);

    lissoc = socket(AF_INET, SOCK_STREAM, 0);
    if(lissoc < 0){
        perror("socket error");
        exit(-1);
    }

    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family=AF_INET;
    srv_addr.sin_port=htons(port);
    inet_pton(AF_INET, "127.0.0.1", &srv_addr.sin_addr);

    checkreturnint(bind(lissoc, (struct sockaddr*)& srv_addr, sizeof(srv_addr)), "bind error");
    checkreturnint(listen(lissoc, 10), "listen error");

    FD_SET(0, &master); //Inserisco socket stdin tra i socket monitorati dalla select
    FD_SET(lissoc,&master);

    int fdmax;
    fdmax=lissoc;
    
    printf("Server is ready to receive requests!\n");
    fflush(stdout);

    int selind;
    while(1){
        copy = master;
        select(fdmax+1, &copy, NULL, NULL, NULL);
        //In copy vengono lasciati solo i socket pronti. I socket pronti in ascolto diventano pronti 
        // quando c'è una nuova connessione mentre quelli di connessione diventano pronti quando c'è 
        // un nuovo dato
        for(selind = 0; selind <= fdmax; selind++){
            if(FD_ISSET(selind, &copy)){
                if(selind == 0){ //Socket pronto = stdin
                    // commands
                }
                else if(selind == lissoc){ //Pronto il codice di ascolto: nuovo dispositivo connesso
                    int len = sizeof(server_addr);
                    connectsoc = accept(lissoc, (struct sockaddr*) &server_addr, &len);
                    if(connectsoc == -1){
                        perror("accept error");
                        return -1;
                    }
                    FD_SET(connectsoc, &master); //Inserisco nuovo socket in fd_set master
                    checkreturnint(addclient(clients, connectsoc, 0), "addclient error");
                    printf("Client #%d connected\n", connectsoc);
                    if(connectsoc > fdmax) fdmax = connectsoc;
                }
                else{
                    //Operazione sul socket di connessione
                    //Qua faccio uno switch per verificare quale tipologia di dispositivo è. In questo modo posso differenziare le operazioni. Per fare ciò recupero le informazioni dal file
                    //Delle connessioni attive.

                    char cmd[CMDLEN];
                    checkreturnint(recv(selind, (void*)&cmd, CMDLEN, 0), "recv hello error");                    
                    printf("Received: %s\n", cmd);
                    if(strcmp(cmd, "hello") != 0){
                        printf("Client disconnected\n");
                        FD_CLR(selind, &master);
                        checkreturnint(removeclient(clients, selind), "removeclient error");
                        close(selind);
                        fflush(stdout);
                        continue;
                    }
                    
                    if(send(selind, (void*)&cert_len_n, sizeof(uint32_t), 0) < 0){
                        perror("Failed to send certificate length");
                        EVP_PKEY_free(server_pub_key);
                        X509_free(server_cert);
                        return 1;
                    }
                    if(send(selind, (void*)cert_buf, cert_len, 0) < 0){
                        perror("Failed to send certificate");
                        EVP_PKEY_free(server_pub_key);
                        X509_free(server_cert);
                        return 1;
                    }

                    // creating the DH parameters
                    // generate DH parameters using RFC 5114: p and g are fixed
                    EVP_PKEY* dh_params;
                    dh_params = EVP_PKEY_new();
                    EVP_PKEY_set1_DH(dh_params, DH_get_2048_224());

                    // generating the server public-private key pair
                    EVP_PKEY_CTX* pkDHctx = EVP_PKEY_CTX_new(dh_params, NULL);
                    if (!pkDHctx){
                        perror("Failed to create EVP_PKEY_CTX");
                        EVP_PKEY_free(dh_params);
                        return 1;
                    }
                    EVP_PKEY* server_keypair = NULL;
                    if(EVP_PKEY_keygen_init(pkDHctx) <= 0){
                        perror("Failed to initialize key generation");
                        EVP_PKEY_CTX_free(pkDHctx);
                        EVP_PKEY_free(dh_params);
                        return 1;
                    }
                    if(EVP_PKEY_keygen(pkDHctx, &server_keypair) <= 0){
                        perror("Failed to generate key pair");
                        EVP_PKEY_CTX_free(pkDHctx);
                        EVP_PKEY_free(dh_params);
                        return 1;
                    }

                    // Extract the DH structure from the EVP_PKEY structure
                    DH* dh = EVP_PKEY_get1_DH(server_keypair);
                    if (!dh) {
                        perror("Failed to extract DH structure from key pair");
                        EVP_PKEY_free(server_keypair);
                        EVP_PKEY_CTX_free(pkDHctx);
                        EVP_PKEY_free(dh_params);
                        return 1;
                    }

                    // Extract the public key from the DH structure
                    const BIGNUM* pub_key_srv;
                    const BIGNUM* priv_key_srv;
                    DH_get0_key(dh, &pub_key_srv, &priv_key_srv); // Second argument is for the private key

                    // Convert the public key from BIGNUM to string
                    char* pub_key_str = BN_bn2hex(pub_key_srv);
                    if (!pub_key_str) {
                        perror("Failed to convert public key to string");
                        DH_free(dh);
                        EVP_PKEY_free(server_keypair);
                        EVP_PKEY_CTX_free(pkDHctx);
                        EVP_PKEY_free(dh_params);
                        return 1;
                    }
                    
                    // Receive the length of the serialized public key buffer
                    uint32_t pub_key_len_n;
                    int bytes_received = recv(selind, (void*)&pub_key_len_n, sizeof(uint32_t), 0);
                    if (bytes_received < 0) {
                        perror("Error receiving public key length");
                        return 1;
                    }

                    // Convert the length back to host byte order
                    uint32_t pub_key_len = ntohl(pub_key_len_n);

                    // Allocate memory for the serialized public key buffer
                    unsigned char* pub_key_buf = malloc(pub_key_len);
                    if (!pub_key_buf) {
                        perror("Error allocating memory for public key");
                        return 1;
                    }

                    // Receive the serialized public key
                    bytes_received = recv(selind, (void*)pub_key_buf, pub_key_len, 0);
                    if (bytes_received < 0) {
                        perror("Error receiving public key");
                        free(pub_key_buf);
                        return 1;
                    }
/*
                    printf("Serialized public key length: %d\n", pub_key_len);
                    printf("Serialized public key:\n");
                    for (int i = 0; i < pub_key_len; i++) {
                        printf("%02x", pub_key_buf[i]);
                    }
                    printf("\n");
*/

                    // Deserialize the public key
                    EVP_PKEY* client_public_key = d2i_PUBKEY(NULL, (const unsigned char**)&pub_key_buf, pub_key_len);
                    if (!client_public_key) {
                        perror("Error deserializing public key");
                        free(pub_key_buf);
                        return 1;
                    }
                    printf("public key received from client\n");
                    fflush(stdout);

                    //serialize the public key
                    unsigned char* srv_pkey_buf = NULL;
                    int srv_pub_key_len = i2d_PUBKEY(server_keypair, &srv_pkey_buf);
                    if (srv_pub_key_len < 0) {
                        perror("Failed to serialize public key");
                    }
/*
                    // print the serialized public key
                    printf("Serialized public key: \n");
                    for (int i = 0; i < pub_key_len; i++){
                        printf("%02x", srv_pkey_buf[i]);
                    }
                    printf("\n");
*/
                    // Send the length of the serialized public key buffer
                    uint32_t srv_pub_key_len_n = htonl(srv_pub_key_len);
                    checkreturnint(send(selind, (void*)&srv_pub_key_len_n, sizeof(uint32_t), 0), "Error sending public key length");

                    printf("public key length sent to server\n");
                    fflush(stdout);
    
                    // Send the serialized public key to the server
                    checkreturnint(send(selind, (void*)srv_pkey_buf, srv_pub_key_len, 0), "Error sending public key");

                    printf("public key sent to client\n");
                    fflush(stdout);
                    
                    // sign the public key
                    unsigned char* signature;
                    int signature_len;
                    signature = (unsigned char*)malloc(EVP_PKEY_size(rsa_priv_key));

                    // sign public key with function
                    sign_message(srv_pkey_buf, srv_pub_key_len, signature, &signature_len);

                    // send signature length to the client
                    uint32_t signature_len_n = htonl(signature_len);
                    checkreturnint(send(selind, (void*)&signature_len_n, sizeof(uint32_t), 0), "Error sending signature length");
                    // send the signature to the client
                    checkreturnint(send(selind, (void*)signature, signature_len, 0), "Error sending signature");

                    // Generate the shared secret
                    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(server_keypair, NULL);
                    EVP_PKEY_derive_init(ctx_drv);
                    EVP_PKEY_derive_set_peer(ctx_drv, client_public_key);
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
                    // generate the parameters for AES 256 CBC encryption
                    // computing SHA256 hash of the shared secret
                    unsigned char* AES_256_key;
                    int AES_256_key_len;
                    EVP_MD_CTX* keyctx;
                    AES_256_key = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
                    keyctx = EVP_MD_CTX_new();
                    EVP_DigestInit(keyctx, EVP_sha256());
                    EVP_DigestUpdate(keyctx,(unsigned char*)shared_secret, shared_secret_len);
                    EVP_DigestFinal(keyctx, AES_256_key, (unsigned int*)&AES_256_key_len);
                    EVP_MD_CTX_free(keyctx);

                    // print the AES 256 key
                    printf("AES 256 key: \n");
                    for (int i = 0; i < AES_256_key_len; i++){
                        printf("%02x", AES_256_key[i]);
                    }
                    printf("\n");


                    // generate a random IV
                    unsigned char* iv = (unsigned char*)malloc(16);
                    // send IV
                    iv_comm(selind, iv, shared_secret, shared_secret_len);
                    // generate a random nonce
                    RAND_poll();
                    unsigned char nonce[32];
                    memset(nonce, 0, 32);
                    RAND_bytes(nonce, 32);

                    // print the nonce
                    printf("Nonce: ");
                    for (int i = 0; i < 32; i++){
                        printf("%02x", nonce[i]);
                    }
                    printf("\n");

                    // encrypt the nonce with AES 256 CBC
                    printf("AES 256 key: \n");
                    for (int i = 0; i < AES_256_key_len; i++){
                        printf("%02x", AES_256_key[i]);
                    }
                    printf("\n");
                    printf("IV: \n");
                    for (int i = 0; i < 16; i++){
                        printf("%02x", iv[i]);
                    }
                    EVP_CIPHER_CTX* ctx_nonceenc;
                    ctx_nonceenc = EVP_CIPHER_CTX_new();
                    EVP_EncryptInit(ctx_nonceenc, EVP_aes_256_cbc(), AES_256_key, iv);
                    unsigned char* enc_nonce;
                    int enc_nonce_len;
                    int outlen;
                    enc_nonce = (unsigned char*)malloc(32 + 16);
                    EVP_EncryptUpdate(ctx_nonceenc, enc_nonce, &outlen, (unsigned char*)nonce, 32);
                    enc_nonce_len = outlen;
                    EVP_EncryptFinal(ctx_nonceenc, enc_nonce + enc_nonce_len, &outlen);
                    enc_nonce_len += outlen;

                    // print the encrypted nonce
                    printf("Encrypted nonce: ");
                    for (int i = 0; i < enc_nonce_len; i++){
                        printf("%02x", enc_nonce[i]);
                    }
                    printf("\n");
    

                    // send the encrypted nonce length to the client
                    uint32_t enc_nonce_len_n = htonl(enc_nonce_len);
                    checkreturnint(send(selind, (void*)&enc_nonce_len_n, sizeof(uint32_t), 0), "error sending encrypted nonce lenght");
                    printf("encrypted nonce length sent\n");
                    
                    // send the encrypted nonce to the client
                    checkreturnint(send(selind, (void*)enc_nonce, enc_nonce_len, 0), "error sending encrypted nonce");
                    printf("encrypted nonce sent\n");


                    int nonce_len = 32;

                    // reverse the nonce
                    for (int i = 0; i <  nonce_len/ 2; i++){
                        unsigned char tmp = nonce[i];
                        nonce[i] = nonce[nonce_len - i - 1];
                        nonce[nonce_len - i - 1] = tmp;
                    }

    
                    // receive the IV from the client
                    unsigned char* received_iv;
                    received_iv = (unsigned char*)malloc(16);
                    checkreturnint(recv(selind, (void*)received_iv, 16, 0), "error receiving IV");

                    // print the received IV
                    printf("Received IV: ");
                    for (int i = 0; i < 16; i++){
                        printf("%02x", received_iv[i]);
                    }
                    printf("\n");

                    // receive the encrypted structure length
                    uint32_t enc_struct_len_n;
                    checkreturnint(recv(selind, (void*)&enc_struct_len_n, sizeof(uint32_t), 0),"error receiving encrypted structure length");
                    uint32_t enc_struct_len = ntohl(enc_struct_len_n);

                    // receive the encrypted structure
                    unsigned char* enc_struct;
                    enc_struct = (unsigned char*)malloc(enc_struct_len);
                    checkreturnint(recv(selind, (void*)enc_struct, enc_struct_len, 0), "error receiving encrypted structure");
                    
                    time_t t = time(NULL);
                    struct tm tm = *localtime(&t);
                    char timestamp[DATE_LEN];

                    struct recv_data{
                        char ts[DATE_LEN];
                        unsigned char hmac[EVP_MAX_MD_SIZE];
                    };

                    // decrypt the structure
                    EVP_CIPHER_CTX* ctx_structdec;
                    ctx_structdec = EVP_CIPHER_CTX_new();
                    EVP_DecryptInit(ctx_structdec, EVP_aes_256_cbc(), AES_256_key, received_iv);
                    unsigned char* dec_struct;
                    int dec_struct_len;
                    dec_struct = (unsigned char*)malloc(enc_struct_len);
                    EVP_DecryptUpdate(ctx_structdec, dec_struct, &outlen, enc_struct, enc_struct_len);
                    dec_struct_len = outlen;
                    EVP_DecryptFinal(ctx_structdec, dec_struct + dec_struct_len, &outlen);
                    dec_struct_len += outlen;
                    EVP_CIPHER_CTX_free(ctx_structdec);

                    struct recv_data recv_auth;
                    memcpy(&recv_auth, dec_struct, sizeof(recv_auth));

                    // print the decrypted structure
                    printf("Decrypted structure: \n");
                    printf("Timestamp: %s\n", recv_auth.ts);
                    printf("Received HMAC: ");
                    for (int i = 0; i < EVP_MD_size(EVP_sha256()); i++){
                        printf("%02x", recv_auth.hmac[i]);
                    }
                    printf("\n");

                    // obtain the current timestamp
                    time_t now = time(NULL);
                    struct tm tm_now = *localtime(&now);
                    char now_str[DATE_LEN];
                    // timestamp format: YYYY-MM-DD HH:MM:SS
                    sprintf(now_str, "%d-%02d-%02d %02d:%02d:%02d", tm_now.tm_year + 1900, tm_now.tm_mon + 1, tm_now.tm_mday, tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec);

                    // compare the timestamps: the received timestamp (recv_auth.ts) must be within 2 minutes from the current timestamp
                    struct tm recv_tm;
                    strptime(recv_auth.ts, "%Y-%m-%d %H:%M:%S", &recv_tm);
                    time_t recv_time = mktime(&recv_tm);
                    time_t diff = difftime(now, recv_time);
                    if (diff > 120){
                        printf("Timestamps differ by more than 2 minutes, connection aborted\n");
                        exit(-1);
                    }
                    else{
                        printf("Timestamps differ by less than 2 minutes, connection accepted\n");
                    }

                    // compute the HMAC of the nonce by using the function
                    unsigned char* computed_hmac_nonce;
                    unsigned int computed_hmac_nonce_len;
                    computed_hmac_nonce = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
                    printf("Nonce: ");
                    for (int i = 0; i < nonce_len; i++){
                        printf("%02x", nonce[i]);
                    }
                    compute_hmac(nonce, nonce_len, shared_secret, shared_secret_len, computed_hmac_nonce, &computed_hmac_nonce_len);
                    printf("Computed HMAC of the nonce: ");
                    for (int i = 0; i < computed_hmac_nonce_len; i++){
                        printf("%02x", computed_hmac_nonce[i]);
                    }
                    printf("\n");

                    // compare the HMACs
                    if(CRYPTO_memcmp(computed_hmac_nonce, recv_auth.hmac, computed_hmac_nonce_len) == 0){
                        printf("HMACs match, authentication complete\n");
                    }
                    else{
                        printf("HMACs do not match, connection aborted\n");
                    }


                    checkreturnint(recv(selind, (void*)&cmd, CMDLEN, 0), "recv of command error");                    
                    if (strcmp(cmd, "register") == 0) {
                        printf("Registering user...\n");

                    } else if (strcmp(cmd, "login") == 0) {
                        printf("Logging in user with username\n");

                    } else if (strcmp(cmd, "list") == 0) {
                        printf("Listing items...\n");

                    } else if (strcmp(cmd, "get") == 0) {
                        printf("Getting item\n");

                    } else if (strcmp(cmd, "add") == 0) {
                        printf("Adding item\n");

                    } else if (strcmp(cmd, "logout") == 0) {
                        printf("Client #%d exited\n", selind);
                        FD_CLR(selind, &master);
                        close(selind);
                        checkreturnint(removeclient(clients, selind), "removeclient error");
                        fflush(stdout);
                        continue;
                    } else {
                        printf("Invalid cmd received.\n");
                    }
                }
            }
        }  
    }
    EVP_PKEY_free(server_pub_key);
    X509_free(server_cert);
    free(cert_buf);
}