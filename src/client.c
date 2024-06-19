#include "utils.h"

void help(){
    puts(" ┌───────────────────────────────────────────────────────┐");
    puts(" │ Welcome to Bulletin Board System!                     │");
    puts(" │                                                       │");
    puts(" │ Available commands:                                   │");
    puts(" │ register <email> <username> <password>                │");
    puts(" │ login <username> <password>                           │");
    puts(" │ logout                                                │");
    puts(" │ list <n>             (to print latest n messages)     │");
    puts(" │ get <mid>            (to download a message content)  │");
    puts(" │ add <title> <body>   (to add a message to BBS)        │");
    puts(" └───────────────────────────────────────────────────────┘");
}

int lissoc = 0;

void handle_sig(int sig) {
    printf("\nCaught signal %d, closing socket and exiting...\n", sig);
    checkreturnint(send(lissoc, (void*)"logout", CMDLEN, 0), "error sending logout req");
    close(lissoc);
    exit(0);
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
    checkreturnint(send(lissoc, (void*)"hello", CMDLEN, 0), "error sending hello");

    puts("Receiving certificate from server");
    // receiving server certificate from socket
    X509* server_cert;
    uint32_t cert_len;
    checkreturnint(recv(lissoc, (void*)&cert_len, sizeof(uint32_t), 0), "error receiving server cert");
    long cert_len_long = ntohl(cert_len);
    unsigned char* cert_buffer = (unsigned char*)malloc(cert_len_long);
    checkreturnint(recv(lissoc, (void*)cert_buffer, cert_len_long, 0), "error receiving server certificate");

    // printing serialized certificate
    /*
    printf("Serialized certificate: \n");
    for (int i = 0; i < cert_len_long; i++){
        printf("%02x", cert_buffer[i]);
    }
    printf("\n\n");
    */
    // deserialize certificate using d2i_X509
    server_cert = d2i_X509(NULL, (const unsigned char**)&cert_buffer, cert_len_long);
    checkrnull(server_cert, "error deserializing server certificate");

    // extracting RSA public key from certificate
    // puts("Extracting RSA public key from certificate");
    EVP_PKEY* server_pubkey = X509_get_pubkey(server_cert);
    checkrnull(server_pubkey, "error extracting public key from certificate");
    // printing public key information
    RSA* rsa_pubkey = EVP_PKEY_get1_RSA(server_pubkey);
    checkrnull(rsa_pubkey, "error extracting RSA public key");
    /*
    printf("RSA public key: \n");
    printf("Modulus: %s\n", BN_bn2hex(RSA_get0_n(rsa_pubkey)));
    printf("Exponent: %s\n", BN_bn2hex(RSA_get0_e(rsa_pubkey)));
    */
    RSA_free(rsa_pubkey);

    // at the moment we assume that the certificate is valid hence it's self signed
    // we don't request the client to send its certificate for simplicity

    // generate DH parameters using RFC 5114: p and g are fixed
    EVP_PKEY* dh_params;
    dh_params = EVP_PKEY_new();
    EVP_PKEY_set1_DH(dh_params, DH_get_2048_224());

    // generating the client public-private key pair
    EVP_PKEY_CTX* pkDHctx = EVP_PKEY_CTX_new(dh_params, NULL);
    checkrnull(pkDHctx, "error creating EVP_PKEY_CTX");
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
/*
    // print the serialized public key
    printf("Serialized public key: \n");
    for (int i = 0; i < pub_key_len; i++){
        printf("%02x", pub_key_buf[i]);
    }
    printf("\n");
*/
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
        printf("Signature verified, parameters accepted\n");
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

    // Generate the shared secret
    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(client_keypair, NULL);
    EVP_PKEY_derive_init(ctx_drv);
    EVP_PKEY_derive_set_peer(ctx_drv, server_pub_key);
    unsigned char* shared_secret;

    size_t shared_secret_len;
    EVP_PKEY_derive(ctx_drv, NULL, &shared_secret_len);

    shared_secret = (unsigned char*)malloc(shared_secret_len);
    EVP_PKEY_derive(ctx_drv, shared_secret, &shared_secret_len);
    printf("shared secret len: %zu\n" , shared_secret_len);
    // Print the shared secret
/*  printf("Shared secret: \n");
    for (int i = 0; i < shared_secret_len; i++) {
        printf("%02x", shared_secret[i]);
    }
    printf("\n"); 
*/

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
/* 
    printf("AES 256 key: \n");
    for (int i = 0; i < AES_256_key_len; i++){
        printf("%02x", AES_256_key[i]);
    }
 */
    unsigned char* srv_iv = malloc(IV_SIZE);
    if(receiveIVHMAC(lissoc, srv_iv, shared_secret, shared_secret_len) < 0){
        close(lissoc);
        exit(-1);
    }
 /*    printf("srv_iv: \n");
    for (int i = 0; i < 16; i++){
        printf("%02x", srv_iv[i]);
    }
     */
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
/*     printf("\n Encrypted Nonce: \n");
    for (int i = 0; i < nonce_len; i++){
        printf("%02x", nonce[i]);
    }
    printf("\n"); */
    // decrypting the nonce using the decryption funciton
    unsigned char decrypted_nonce[nonce_len];
    int decrypted_nonce_len;
    decrypt_message(nonce, nonce_len, AES_256_key, srv_iv, decrypted_nonce, &decrypted_nonce_len);
    // print the decrypted nonce
/*     printf("\n Decrypted Nonce: \n");
    for (int i = 0; i < decrypted_nonce_len; i++){
        printf("%02x", decrypted_nonce[i]);
    }
    printf("\n"); */
    for (int i = 0; i < decrypted_nonce_len/2; i++){
        unsigned char temp = decrypted_nonce[i];
        decrypted_nonce[i] = decrypted_nonce[decrypted_nonce_len - i - 1];
        decrypted_nonce[decrypted_nonce_len - i - 1] = temp;
    }
/* 
    printf("\n Reversed Nonce: \n");
    for (int i = 0; i < decrypted_nonce_len; i++){
        printf("%02x", decrypted_nonce[i]);
    }
    printf("\n");
 */
    // computing the HMAC of the nonce
    unsigned char* hmac = (unsigned char*)malloc(HMAC_SIZE);
    unsigned int hmac_len;
    compute_hmac(decrypted_nonce, decrypted_nonce_len, shared_secret, shared_secret_len, hmac, &hmac_len);

/* 
    // print the HMAC
    printf("\n");
    printf("HMAC: ");
    for (int i = 0; i < hmac_len; i++){
        printf("%02x", hmac[i]);
    }
    printf("\n");
     */

    // generating the IV for AES encryption
    unsigned char iv2 [16];
    RAND_bytes(iv2, 16);
    // sending the IV
    ret = send(lissoc, (void*)iv2, 16, 0);
    if (ret < 0){
        perror("error sending IV");
        exit(-1);
    }

/* 
    // print the IV 
    printf("IV2: \n");
    for (int i = 0; i < 16; i++){
        printf("%02x", iv2[i]);
    }
    printf("\n");
 */
    

/*     
    // print the encrypted structure
    printf("Encrypted structure: \n");
    for (int i = 0; i < encrypted_len; i++){
        printf("%02x", encrypted_struct[i]);
    }
    printf("\n");
 */
    // creating structure to hold nonce hmac and timestamp
    MessageAuth nonceauth = createMessageAuth(hmac, hmac_len);
    // encrypting the structure
    unsigned char* encrypted_auth = (unsigned char*)malloc(sizeof(MessageAuth)+16);
    int encrypted_len;
    encrypt_message((unsigned char*)&nonceauth, sizeof(MessageAuth), AES_256_key, iv2, encrypted_auth, &encrypted_len);
    // send the encrypted structure
    uint32_t encrypted_len_n = htonl(encrypted_len);
    checkreturnint(send(lissoc, (void*)&encrypted_len_n, sizeof(uint32_t), 0), "error sending encrypted structure length");
    checkreturnint(send(lissoc, (void*)encrypted_auth, encrypted_len, 0), "error sending encrypted structure");
    puts("Handshake successfully completed!");
    
    // Client's command parsing loop
    char input[BUF_SIZE];
    help();

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
            char* email = arg;
            char* username = strtok(NULL, " ");
            char* password = strtok(NULL, " ");
            char* rest = strtok(NULL, "/0");
            if(!email || !username || !password){
                puts("Missing argument!\nUsage: register <email> <username> <password>");
                continue;
            }
            if(rest){
                puts("Too many arguments.");
                continue;
            }

            puts("Sending register to server");
            checkreturnint(send(lissoc, (void*)"register", CMDLEN, 0), "error sending register");

            unsigned char* pwd_hash = (unsigned char*)malloc(HASH_SIZE);
            if(!pwd_hash){
                perror("memory finished");
                exit(EXIT_FAILURE);
            }
            compute_sha256((unsigned char*)password, strlen(password), pwd_hash);
            
            char pwd_hash_hex[65];
            for (int i = 0; i < 32; ++i) {
                sprintf(&pwd_hash_hex[i*2], "%02x", pwd_hash[i]);
            }
            pwd_hash_hex[64] = 0;
            //generate timestamp string with create_timestamp
            char* reg_timestamp = create_timestamp();
            printf("timestamp: %s\n", reg_timestamp);
            int total_len = strlen(email)+strlen(username)+strlen(pwd_hash_hex)+strlen(reg_timestamp)+4;
            char* tosend = calloc(total_len, sizeof(char));
            if (!tosend){
                perror("Error creating packet..");
                continue;
            };

            // build a string tosend with email, username, password hash and timestamp
            snprintf(tosend, total_len, "%s,%s,%s,%s", email, username, pwd_hash_hex, reg_timestamp);
            printf("tosend: %s\n", tosend);
            printf("tosend lenght: %ld\n", strlen(tosend));
            
            // generating IV for AES encryption
            unsigned char* iv = (unsigned char*)malloc(IV_SIZE);
            iv_comm(lissoc, iv, shared_secret, shared_secret_len);
            // encrypting with AES CBC mode
            unsigned char* ciphertext = (unsigned char*)malloc(sizeof(tosend) + 16);
            int ciphertext_len;
            encrypt_message((unsigned char*)tosend, strlen(tosend), AES_256_key, iv, ciphertext, &ciphertext_len);
            uint32_t ciphertext_len_n = htonl(ciphertext_len);
            printf("Ciphertext length: %d\n", ciphertext_len);
            // print ciphertext as hex
            printf("Ciphertext: ");
            for (int i = 0; i < ciphertext_len; i++){
                printf("%02x", ciphertext[i]);
            }
            printf("\n");

            checkreturnint(send(lissoc, (void*)&ciphertext_len_n, sizeof(uint32_t), 0), "error sending ctlen");
            checkreturnint(send(lissoc, ciphertext, ciphertext_len, 0), "error sending ct");

            // computing HMAC over cyphertext
            unsigned char* hmac_reg = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
            unsigned int hmac_reg_len;
            compute_hmac((unsigned char*)ciphertext, ciphertext_len, shared_secret, shared_secret_len, hmac_reg, &hmac_reg_len);
            // sending HMAC
            uint32_t hmac_reg_len_n = htonl(hmac_reg_len);
            printf("HMAC length: %d\n", hmac_reg_len);
            printf("HMAC: ");
            for (int i = 0; i < hmac_reg_len; i++){
                printf("%02x", hmac_reg[i]);
            }
            printf("\n");
            checkreturnint(send(lissoc, (void*)&hmac_reg_len_n, sizeof(uint32_t), 0), "error sending hmac len");
            checkreturnint(send(lissoc, hmac_reg, hmac_reg_len, 0), "error sending hmac");
            // receiving "ok" from server
            char* response = (char*)malloc(CMDLEN);
            puts("receiving response");
            checkreturnint(recv(lissoc, (void*)response, CMDLEN, 0), "error receiving response");
            if (strcmp(response, "ok") == 0){
                puts("Registration successful!");
            } else if(strcmp(response, "exists") == 0){
                puts("Username already used, try again.");
            } else {
                puts("Registration failed, try again.");
            }

        } else if (strcmp(input, "login") == 0) {            
            char* username = arg;
            char* password = strtok(NULL, " ");
            char* rest = strtok(NULL, "/0");
            if(!username || !password){
                puts("Missing argument!\nUsage: login <username> <password>");
                continue;
            }
            if(rest){
                puts("Too many arguments.");
                continue;
            }
            unsigned char* pwd_hash = (unsigned char*)malloc(HASH_SIZE);
            if(!pwd_hash){
                perror("memory finished");
                exit(EXIT_FAILURE);
            }
            checkreturnint(send(lissoc, (void*)"login", CMDLEN, 0), "error sending login");
            compute_sha256((unsigned char*)password, strlen(password), pwd_hash);
            int total_len = strlen(username)+strlen(password);
            char* tosend = malloc(total_len+2);
            if (!tosend){
                perror("Error creating packet..");
                continue;
            };
            snprintf(tosend, total_len+2, "%s,%s", username, pwd_hash);

            puts("Logging in...");

        } else if (strcmp(input, "list") == 0) {
            int n = atoi(arg);
            char* rest = strtok(NULL, "/0");
            if(rest){
                puts("Too many arguments.");
                continue;
            }
            // checking overflows
            if(n < 0){
                puts("Invalid n, try again");
                continue;
            }
            char* tosend = malloc(CMDLEN+sizeof(n));
            snprintf(tosend, CMDLEN+sizeof(n), "%s,%s", "login", arg);

            puts("Listing n messages...");

        } else if (strcmp(input, "get") == 0) {
            int mid = atoi(arg);
            char* rest = strtok(NULL, "/0");
            if(rest){
                puts("Too many arguments.");
                continue;
            }
            if(mid < 0){
                puts("Invalid mid, try again");
                continue;
            }
            char* tosend = malloc(CMDLEN+sizeof(mid));
            snprintf(tosend, CMDLEN+sizeof(mid), "%s,%s", "get", arg);

            printf("Downloading message with mid=%d\n",mid);
        } else if (strcmp(input, "add") == 0) {
            char* title = arg;
            char* body = strtok(NULL, "\0");
            char* tosend = malloc(CMDLEN+strlen(title)+strlen(body));
            snprintf(tosend, CMDLEN+strlen(title)+strlen(body), "%s,%s,%s", "add", title, body);
            puts("Posting message...");
        } else if (strcmp(input, "logout") == 0) {
            printf("Logging out...\n");
            checkreturnint(send(lissoc, (void*)"logout", CMDLEN, 0), "error sending logout req");
            close(lissoc);
            break;
        } else if (strcmp(input, "help") == 0) {
            help();
        } else {
            printf("Invalid choice, please try again.\n");
        }
    }
    checkreturnint(send(lissoc, (void*)"logout", CMDLEN, 0), "error sending logout req");
    close(lissoc);
    return 0;
}
