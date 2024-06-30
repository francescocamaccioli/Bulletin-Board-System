#include "utils.h"
#include <regex.h>

int lissoc = 0;
int login = 0;
int regexcheckon = 0; // 1 if to turn regex check on, 0 if off
unsigned char shared_secret[HASH_SIZE];
unsigned char* AES_256_key[HASH_SIZE];


void help(){
    puts("  ┌───────────────────────────────────────────────────────┐");
    puts("  │ Welcome to Bulletin Board System!                     │");
    puts("  │                                                       │");
    puts("  │ Available commands:                                   │");
    puts("  │ register <email> <username> <password>                │");
    puts("  │ login <username> <password>                           │");
    puts("  │ logout                                                │");
    puts("  │ list <n>             (to print latest n messages)     │");
    puts("  │ get <mid>            (to download a message content)  │");
    puts("  │ add <title> <body>   (to add a message to BBS)        │");
    puts("  └───────────────────────────────────────────────────────┘");
}

void handle_sig(int sig) {
    printf("\nCaught signal %d, closing socket and exiting...\n", sig);
    checkreturnint(send(lissoc, (void*)"quit", CMDLEN, 0), "error sending quit");
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
    
    FILE *server_cert_file = fopen("server_cert_mykey.pem", "r");
    checkrnull(server_cert_file, "Failed to open server certificate file");
    X509* server_cert;
    server_cert = PEM_read_X509(server_cert_file, NULL, NULL, NULL);
    checkrnull(server_cert, "Failed to read server certificate");
    fclose(server_cert_file);

    //extract public key from server certificate
    EVP_PKEY* server_pubkey = X509_get_pubkey(server_cert);
    checkrnull(server_pubkey, "Failed to extract server public key");

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
        printf("Signature verified\n");
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
    
    size_t shared_secret_len;
    EVP_PKEY_derive(ctx_drv, NULL, &shared_secret_len);

    unsigned char* shared_secret_init = (unsigned char*)malloc(shared_secret_len);
    EVP_PKEY_derive(ctx_drv, shared_secret_init, &shared_secret_len);

    // hashing the shared secret to obtain the AES 256 key
    unsigned char* AES_256_key;
    int AES_256_key_len;
    EVP_MD_CTX* keyctx;
    AES_256_key = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    keyctx = EVP_MD_CTX_new();
    EVP_DigestInit(keyctx, EVP_sha256());
    EVP_DigestUpdate(keyctx,(unsigned char*)shared_secret_init, shared_secret_len);
    EVP_DigestFinal(keyctx, AES_256_key, (unsigned int*)&AES_256_key_len);
    EVP_MD_CTX_free(keyctx);

    // reversing the shared secret init
    for (int i = 0; i < shared_secret_len/2; i++){
        unsigned char temp = shared_secret_init[i];
        shared_secret_init[i] = shared_secret_init[shared_secret_len - i - 1];
        shared_secret_init[shared_secret_len - i - 1] = temp;
    }

    
    // computing the hash of the shared secret
    compute_sha256(shared_secret_init, shared_secret_len, shared_secret);
    shared_secret_len = HASH_SIZE;
    printf("Shared secret HASH: ");
    for (int i = 0; i < shared_secret_len; i++){
        printf("%02x", shared_secret_init[i]);
    }
    printf("\n");
    free(shared_secret_init);

    unsigned char* srv_iv = malloc(IV_SIZE);
    if(receiveIVHMAC(lissoc, srv_iv, shared_secret, shared_secret_len) < 0){
        close(lissoc);
        exit(-1);
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

    // decrypting the nonce using the decryption function
    unsigned char decrypted_nonce[nonce_len];
    int decrypted_nonce_len;
    decrypt_message(nonce, nonce_len, AES_256_key, srv_iv, decrypted_nonce, &decrypted_nonce_len);

    for (int i = 0; i < decrypted_nonce_len/2; i++){
        unsigned char temp = decrypted_nonce[i];
        decrypted_nonce[i] = decrypted_nonce[decrypted_nonce_len - i - 1];
        decrypted_nonce[decrypted_nonce_len - i - 1] = temp;
    }

    // computing the HMAC of the nonce
    unsigned char* hmac = (unsigned char*)malloc(HMAC_SIZE);
    unsigned int hmac_len;
    compute_hmac(decrypted_nonce, decrypted_nonce_len, shared_secret, shared_secret_len, hmac, &hmac_len);

    // generating the IV for AES encryption
    unsigned char iv2 [16];
    RAND_bytes(iv2, 16);
    // sending the IV
    ret = send(lissoc, (void*)iv2, 16, 0);
    if (ret < 0){
        perror("error sending IV");
        exit(-1);
    }

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
    free(pksign);
    free(srv_iv);
    free(nonce);
    free(hmac);
    free(encrypted_auth);
    DH_free(dh);
    EVP_PKEY_free(client_keypair);
    EVP_PKEY_CTX_free(pkDHctx);
    EVP_PKEY_free(dh_params);

    // receive response from server
    char* response = (char*)malloc(CMDLEN);
    checkreturnint(recv(lissoc, (void*)response, CMDLEN, 0), "error receiving response");
    if (strcmp(response, "ok") != 0){
        puts(RED"Handshake failed, aborting."RESET);
        exit(-1);
    }
    free(response);
    puts(GREEN"Handshake successfully completed!"RESET);
    
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
            if(login){
                puts(RED"You are already logged in, please logout first."RESET);
                continue;
            }
            char* email = arg;
            char* username = strtok(NULL, " ");
            char* password = strtok(NULL, " ");
            char* rest = strtok(NULL, "\0");
            if(!email || !username || !password){
                puts(YELLOW"Missing argument!\nUsage: register <email> <username> <password>"RESET);
                continue;
            }
            if(rest){
                puts("Too many arguments.");
                continue;
            }

            if(regexcheckon == 1){
                // Sanitize email, username, and password using regex
                regex_t regex;
                int comp;

                // Email regex pattern
                char* email_pattern = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
                comp = regcomp(&regex, email_pattern, REG_EXTENDED);
                if (comp) {
                    fprintf(stderr, "Could not compile email regex\n");
                    exit(EXIT_FAILURE);
                }

                // Validate email
                comp = regexec(&regex, email, 0, NULL, 0);
                if (comp) {
                    fprintf(stderr, "Invalid email format\n");
                    continue;
                }

                // Username regex pattern
                char* username_pattern = "^[A-Za-z0-9_]{3,20}$";
                comp = regcomp(&regex, username_pattern, REG_EXTENDED);
                if (comp) {
                    fprintf(stderr, "Could not compile username regex\n");
                    exit(EXIT_FAILURE);
                }

                // Validate username
                comp = regexec(&regex, username, 0, NULL, 0);
                if (comp) {
                    fprintf(stderr, "Invalid username format\n");
                    continue;
                }

                // Password regex pattern
                char* password_pattern = "^[A-Za-z\\d\\W_]{16,}$";
                comp = regcomp(&regex, password_pattern, REG_EXTENDED);
                if (comp) {
                    fprintf(stderr, "Could not compile password regex\n");
                    exit(EXIT_FAILURE);
                }

                // Validate password
                comp = regexec(&regex, password, 0, NULL, 0);
                if (!comp) {
                    fprintf(stderr, "Invalid password format\n");
                    continue;
                }

                // Free regex resources
                regfree(&regex);
            }

            unsigned char* pwd_hash = (unsigned char*)malloc(HASH_SIZE);
            if(!pwd_hash){
                perror("memory finished");
                exit(EXIT_FAILURE);
            }
            puts("Sending register to server");
            checkreturnint(send(lissoc, (void*)"register", CMDLEN, 0), "error sending register");
            compute_sha256((unsigned char*)password, strlen(password), pwd_hash);
            
            char pwd_hash_hex[65];
            for (int i = 0; i < 32; ++i) {
                sprintf(&pwd_hash_hex[i*2], "%02x", pwd_hash[i]);
            }
            pwd_hash_hex[64] = 0;
            //generate timestamp string with create_timestamp
            char* reg_timestamp = create_timestamp();
            int total_len = strlen(email)+strlen(username)+strlen(pwd_hash_hex)+strlen(reg_timestamp)+5;
            char* tosend = malloc(total_len);
            if (!tosend){
                perror("Error creating packet..");
                continue;
            };
            
            // build a string tosend with email, username, password hash and timestamp
            snprintf(tosend, total_len, "%s/%s/%s/%s", email, username, pwd_hash_hex, reg_timestamp);
            
            // generating IV for AES encryption
            unsigned char* iv = (unsigned char*)malloc(IV_SIZE);
            // sending it to client with its HMAC
            iv_comm(lissoc, iv, shared_secret, shared_secret_len);
            // encrypting with AES CBC mode
            unsigned char* ciphertext = (unsigned char*)malloc(total_len + 16);
            int ciphertext_len;
            encrypt_message((unsigned char*)tosend, total_len, AES_256_key, iv, ciphertext, &ciphertext_len);
            unsigned char* hmac_reg = (unsigned char*)malloc(HMAC_SIZE);
            unsigned int hmac_reg_len;
            // computing HMAC over cyphertext
            compute_hmac((unsigned char*)ciphertext, ciphertext_len, shared_secret, shared_secret_len, hmac_reg, &hmac_reg_len);
            long sendlen = HMAC_SIZE + ciphertext_len;
            uint32_t sendlen_n = htonl(sendlen);
            unsigned char sendbuf[sendlen];
            concatenate_hmac_ciphertext(hmac_reg, ciphertext, ciphertext_len, sendbuf);
            checkreturnint(send(lissoc, (void*)&sendlen_n, sizeof(uint32_t), 0), "error sending sendlen");
            checkreturnint(send(lissoc, sendbuf, sendlen, 0), "error sending sendbuf");

            // receiving response from server
            char* response = (char*)malloc(CMDLEN);
            checkreturnint(recv(lissoc, (void*)response, CMDLEN, 0), "error receiving response");
            if (strcmp(response, "ok") == 0){
                // receving challenge from server
                unsigned char* challenge[32];
                // reading challenge from file
                FILE* challenge_file = fopen("challenge.txt", "r");
                if (!challenge_file){
                    perror("error opening challenge file");
                    exit(-1);
                }
                fread(challenge, 1, 32, challenge_file);
                fclose(challenge_file);
                remove("challenge.txt");

                // computing HMAC over challenge
                unsigned char* hmac_chal = (unsigned char*)malloc(HMAC_SIZE);
                unsigned int hmac_chal_len;
                compute_hmac((unsigned char*)challenge, 32, shared_secret, shared_secret_len, hmac_chal, &hmac_chal_len);

                // writing the hmac to its file
                FILE* hmac_file = fopen("chall_hmac.txt", "w");
                if (!hmac_file){
                    perror("error opening hmac file");
                    exit(-1);
                }
                fwrite(hmac_chal, 1, HMAC_SIZE, hmac_file);
                fclose(hmac_file);

                // send challenge ready to server
                checkreturnint(send(lissoc, (void*)"ready", CMDLEN, 0), "error sending ready");

                puts(GREEN "Registration successful!" RESET);
            } else if(strcmp(response, "exists") == 0){
                puts(RED "Username already used, try again." RESET);
            } else if(strcmp(response, "timeout") == 0){
                puts(RED "Timeout of 1 minute expired, try again." RESET);
            } else {
                puts(RED "Registration failed, try again." RESET);
            }

        } else if (strcmp(input, "login") == 0) {     
            if(login){
                puts(RED"You are already logged in, please logout first."RESET);
                continue;
            }
            char* username = arg;
            char* password = strtok(NULL, " ");
            char* rest = strtok(NULL, "\0");
            if(!username || !password){
                puts(YELLOW"Missing argument!\nUsage: login <username> <password>"RESET);
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
            char pwd_hash_hex[65];
            for (int i = 0; i < 32; ++i) {
                sprintf(&pwd_hash_hex[i*2], "%02x", pwd_hash[i]);
            }
            pwd_hash_hex[64] = 0;

            // generating timestamp
            char* login_timestamp = create_timestamp();
            int total_len = strlen(username)+strlen(pwd_hash_hex)+strlen(login_timestamp)+4;
            char* tosend = malloc(total_len);
            if (!tosend){
                perror("Error creating packet..");
                continue;
            };
            snprintf(tosend, total_len, "%s/%s/%s", username, pwd_hash_hex, login_timestamp);
            
            // generating IV for AES encryption
            unsigned char* iv = (unsigned char*)malloc(IV_SIZE);
            // sending it to client with its HMAC
            iv_comm(lissoc, iv, shared_secret, shared_secret_len);
            // encrypting with AES CBC mode
            unsigned char* ciphertext = (unsigned char*)malloc(total_len + 16);
            int ciphertext_len;
            encrypt_message((unsigned char*)tosend, total_len, AES_256_key, iv, ciphertext, &ciphertext_len);
            unsigned char* hmac_log = (unsigned char*)malloc(HMAC_SIZE);
            unsigned int hmac_log_len;
            compute_hmac((unsigned char*)ciphertext, ciphertext_len, shared_secret, shared_secret_len, hmac_log, &hmac_log_len);
            long sendlen = HMAC_SIZE + ciphertext_len;
            uint32_t sendlen_n = htonl(sendlen);
            unsigned char sendbuf[sendlen];
            concatenate_hmac_ciphertext(hmac_log, ciphertext, ciphertext_len, sendbuf);
            checkreturnint(send(lissoc, (void*)&sendlen_n, sizeof(uint32_t), 0), "error sending sendlen");
            checkreturnint(send(lissoc, sendbuf, sendlen, 0), "error sending sendbuf");
            printf("Sent login request\n");
            // receiving response from server
            char* response = (char*)malloc(CMDLEN);
            checkreturnint(recv(lissoc, (void*)response, CMDLEN, 0), "error receiving response");
            if (strcmp(response, "ok") == 0){
                login = 1;
                puts(GREEN"Login successful!"RESET);
            } else if(strcmp(response, "nouser") == 0){
                puts(RED"User not found, please register first."RESET);
            } else if(strcmp(response, "wrongpsw") == 0){
                puts(RED"Wrong password, try again."RESET);
            } else if(strcmp(response, "already") == 0){
                puts(RED"User already logged in."RESET);
            } else {
                puts(RED"Login failed, try again."RESET);
            }

        } else if (strcmp(input, "list") == 0) {
            if(!arg){
                puts(YELLOW"Missing argument!\nUsage: list <n>"RESET);
                continue;
            }
            int n = atoi(arg);
            char* rest = strtok(NULL, "\0");
            if(rest){
                puts("Too many arguments.");
                continue;
            }
            // checking overflows
            if(n < 0){
                puts("Invalid n, try again");
                continue;
            }
            checkreturnint(send(lissoc, (void*)"list", CMDLEN, 0), "error sending login");

            char* list_timestamp = create_timestamp();
            int total_len = 4 + strlen(list_timestamp) + 3;
            char* tosend = malloc(total_len);
            if (tosend == NULL) {
                fprintf(stderr, "Memory allocation failed\n");
                return 1;
            }
            snprintf(tosend, total_len, "%d/%s", n, list_timestamp);

            // generating IV for AES encryption
            unsigned char* iv = (unsigned char*)malloc(IV_SIZE);
            // sending it to client with its HMAC
            iv_comm(lissoc, iv, shared_secret, shared_secret_len);
            // encrypting with AES CBC mode
            unsigned char* ciphertext = (unsigned char*)malloc(total_len + 16);
            int ciphertext_len;
            encrypt_message((unsigned char*)tosend, total_len, AES_256_key, iv, ciphertext, &ciphertext_len);
            unsigned char* hmac_log = (unsigned char*)malloc(HMAC_SIZE);
            unsigned int hmac_log_len;
            compute_hmac((unsigned char*)ciphertext, ciphertext_len, shared_secret, shared_secret_len, hmac_log, &hmac_log_len);
            long sendlen = HMAC_SIZE + ciphertext_len;
            uint32_t sendlen_n = htonl(sendlen);
            unsigned char sendbuf[sendlen];
            concatenate_hmac_ciphertext(hmac_log, ciphertext, ciphertext_len, sendbuf);
            checkreturnint(send(lissoc, (void*)&sendlen_n, sizeof(uint32_t), 0), "error sending sendlen");
            checkreturnint(send(lissoc, sendbuf, sendlen, 0), "error sending sendbuf");
            free(tosend);

            char* response = (char*)malloc(CMDLEN);
            // receiving response from server
            checkreturnint(recv(lissoc, (void*)response, CMDLEN, 0), "error receiving response");

            if (strcmp(response, "ok") == 0){
                puts(GREEN"List request accepted!"RESET);
                
                // receiving IV for AES decryption
                unsigned char* iv_list = (unsigned char*)malloc(IV_SIZE);
                receiveIVHMAC(lissoc, iv_list, shared_secret, shared_secret_len);

                // receiving cyphertext lenght
                uint32_t buflen_n;
                checkreturnint(recv(lissoc, (void*)&buflen_n, sizeof(uint32_t), 0), "error receiving buflen");
                long buflen = ntohl(buflen_n);
                int ciphertext_len = buflen - HMAC_SIZE;
                unsigned char* conc_buf = (unsigned char*)malloc(buflen);
                unsigned char* hmac_list = (unsigned char*)malloc(HMAC_SIZE);
                unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
                checkreturnint(recv(lissoc, (void*) conc_buf, buflen, 0), "error receiving concatenated buffer");
                split_hmac_ciphertext(conc_buf, hmac_list, ciphertext, ciphertext_len);
                free(conc_buf);

                // computing HMAC over cyphertext
                unsigned char* hmac_list_check = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
                unsigned int hmac_list_check_len;
                compute_hmac((unsigned char*)ciphertext, ciphertext_len, shared_secret, shared_secret_len, hmac_list_check, &hmac_list_check_len);
                // checking if HMAC is correct
                if (memcmp(hmac_list, hmac_list_check, HMAC_SIZE) != 0){
                    puts("HMAC check failed, aborting.");
                    continue;
                }
                // decrypting the message
                unsigned char* plaintext = (unsigned char*)malloc(ciphertext_len);
                int plaintext_len;
                decrypt_message(ciphertext, ciphertext_len, AES_256_key, iv_list, plaintext, &plaintext_len);

                // split messages from the timestamp
                char* messages = strtok((char*)plaintext, "/");
                char* timestamp = strtok(NULL, "\0");

                // check timestamp
                if (checktimestamp(timestamp) != 0){
                    puts("Timestamp check failed, aborting.");
                    continue;
                }
                else{
                    puts("Timestamp check passed.");
                    // printing the message
                    printf("Latest %d Messages in BBS:\n%s", n, messages);
                }
                free(hmac_list_check);
                free(iv_list);
                free(hmac_list);
            } else if (strcmp(response, "notlogged") == 0){
                puts("You need to login first!");
            } else {
                puts("list failed, try again.");
            }
            free(response);
        } else if (strcmp(input, "get") == 0) {
            if(!arg){
                puts(YELLOW"Missing argument!\nUsage: get <mid>"RESET);
                continue;
            }
            int mid = atoi(arg);
            char* rest = strtok(NULL, "\0");
            if(rest){
                puts("Too many arguments.");
                continue;
            }
            if(mid < 0){
                puts("Invalid mid, try again");
                continue;
            }
            checkreturnint(send(lissoc, (void*)"get", CMDLEN, 0), "error sending get req");

            char* get_timestamp = create_timestamp();
            int total_len = 4 + strlen(get_timestamp) + 3;
            
            char* tosend = malloc(total_len);
            if (tosend == NULL) {
                fprintf(stderr, "Memory allocation failed\n");
                return 1;
            }
            snprintf(tosend, total_len, "%d/%s", mid, get_timestamp);

            // generating IV for AES encryption
            unsigned char* iv = (unsigned char*)malloc(IV_SIZE);
            // sending it to client with its HMAC
            iv_comm(lissoc, iv, shared_secret, shared_secret_len);
            // encrypting with AES CBC mode
            unsigned char* ciphertext = (unsigned char*)malloc(total_len + 16);
            int ciphertext_len;
            encrypt_message((unsigned char*)tosend, total_len, AES_256_key, iv, ciphertext, &ciphertext_len);
            unsigned char* hmac_get = (unsigned char*)malloc(HMAC_SIZE);
            unsigned int hmac_get_len;
            compute_hmac((unsigned char*)ciphertext, ciphertext_len, shared_secret, shared_secret_len, hmac_get, &hmac_get_len);
            long sendlen = HMAC_SIZE + ciphertext_len;
            uint32_t sendlen_n = htonl(sendlen);
            unsigned char sendbuf[sendlen];
            concatenate_hmac_ciphertext(hmac_get, ciphertext, ciphertext_len, sendbuf);

            checkreturnint(send(lissoc, (void*)&sendlen_n, sizeof(uint32_t), 0), "error sending sendlen");
            checkreturnint(send(lissoc, sendbuf, sendlen, 0), "error sending sendbuf");


            char* response = (char*)malloc(CMDLEN);
            // receiving response from server
            checkreturnint(recv(lissoc, (void*)response, CMDLEN, 0), "error receiving response");

            if(strcmp(response, "ok") == 0){
                puts(GREEN"Get request accepted!"RESET);
                // receiving IV for AES decryption
                unsigned char* iv_get = (unsigned char*)malloc(IV_SIZE);
                receiveIVHMAC(lissoc, iv_get, shared_secret, shared_secret_len);

                // receiving cyphertext lenght
                uint32_t buflen_n;
                checkreturnint(recv(lissoc, (void*)&buflen_n, sizeof(uint32_t), 0), "error receiving buflen");
                long buflen = ntohl(buflen_n);
                int ciphertext_len = buflen - HMAC_SIZE;
                unsigned char* conc_buf = (unsigned char*)malloc(buflen);
                unsigned char* hmac_get = (unsigned char*)malloc(HMAC_SIZE);
                unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
                checkreturnint(recv(lissoc, (void*) conc_buf, buflen, 0), "error receiving concatenated buffer");
                split_hmac_ciphertext(conc_buf, hmac_get, ciphertext, ciphertext_len);
                free(conc_buf);

                // computing HMAC over cyphertext
                unsigned char* hmac_get_check = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
                unsigned int hmac_get_check_len;
                compute_hmac((unsigned char*)ciphertext, ciphertext_len, shared_secret, shared_secret_len, hmac_get_check, &hmac_get_check_len);
                // checking if HMAC is correct
                if (memcmp(hmac_get, hmac_get_check, HMAC_SIZE) != 0){
                    puts("HMAC check failed, aborting.");
                    continue;
                }
                // decrypting the message
                unsigned char* plaintext = (unsigned char*)malloc(ciphertext_len);
                int plaintext_len;
                decrypt_message(ciphertext, ciphertext_len, AES_256_key, iv_get, plaintext, &plaintext_len);
                
                // split messages from the timestamp
                char* message = strtok((char*)plaintext, "/");
                char* timestamp = strtok(NULL, "\0");

                // check timestamp
                if (checktimestamp(timestamp) != 0){
                    puts("Timestamp check failed, aborting.");
                    continue;
                }
                else{
                    puts("Timestamp check passed.");
                    // write the message to a file
                    FILE* f = fopen("messages.txt", "a");
                    if (f == NULL){
                        perror("Error opening file");
                        exit(EXIT_FAILURE);
                    }
                    fprintf(f, "%s", message);
                    fclose(f);
                    puts("Message saved to messages.txt");
                }
                free(hmac_get_check);
                free(iv_get);
            } else if (strcmp(response, "notlogged") == 0){
                puts("You need to login first!");
            } else {
                puts("Get failed, try again.");
            }

            free(response);
            free(hmac_get);
            
        } else if (strcmp(input, "add") == 0) {
            char* title = arg;
            char* body = strtok(NULL, "\0");
            
            if(!title || !body){
                puts(YELLOW"Missing argument!\nUsage: add <title> <body>"RESET);
                continue;
            }

            char* tosend = malloc(strlen(title)+strlen(body)+3);
            checkreturnint(send(lissoc, (void*)"add", CMDLEN, 0), "error sending add req");
            int total_len = strlen(title)+strlen(body)+3;
            snprintf(tosend, total_len, "%s/%s", title, body);
            // generating IV for AES encryption
            unsigned char* iv = (unsigned char*)malloc(IV_SIZE);
            // sending it to client with its HMAC
            iv_comm(lissoc, iv, shared_secret, shared_secret_len);
            // encrypting with AES CBC mode
            unsigned char* ciphertext = (unsigned char*)malloc(total_len + 16);
            int ciphertext_len;
            encrypt_message((unsigned char*)tosend, total_len, AES_256_key, iv, ciphertext, &ciphertext_len);
            unsigned char* hmac_add = (unsigned char*)malloc(HMAC_SIZE);
            unsigned int hmac_add_len;
            compute_hmac((unsigned char*)ciphertext, ciphertext_len, shared_secret, shared_secret_len, hmac_add, &hmac_add_len);
            long sendlen = HMAC_SIZE + ciphertext_len;
            uint32_t sendlen_n = htonl(sendlen);
            unsigned char sendbuf[sendlen];
            concatenate_hmac_ciphertext(hmac_add, ciphertext, ciphertext_len, sendbuf);

            checkreturnint(send(lissoc, (void*)&sendlen_n, sizeof(uint32_t), 0), "error sending sendlen");
            checkreturnint(send(lissoc, sendbuf, sendlen, 0), "error sending sendbuf");
            free(tosend);
            free(hmac_add);

            checkreturnint(recv(lissoc, (void*)buffer, BUF_SIZE, 0), "error receiving response");
            if (strcmp(buffer, "ok") == 0){
                puts(GREEN"Message added successfully!"RESET);
            } else if (strcmp(buffer, "notlogged") == 0){
                puts("You need to login first!");
            } else {
                puts("Message add failed, try again.");
            }
        } else if (strcmp(input, "logout") == 0) {
            if(!login){
                puts(RED"You need to login first!"RESET);
                continue;
            }
            printf("Logging out...\n");
            login = 0;
            checkreturnint(send(lissoc, (void*)"logout", CMDLEN, 0), "error sending logout req");

            // receiving response from server
            char* response = (char*)malloc(CMDLEN);
            checkreturnint(recv(lissoc, (void*)response, CMDLEN, 0), "error receiving response");
            if (strcmp(response, "ok") == 0){
                puts(GREEN"Logout successful!"RESET);
            } else {
                puts(RED"Logout failed, try again."RESET);
                continue;
            }

            puts("Executing Handshake for next session...");
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

            size_t shared_secret_len;
            EVP_PKEY_derive(ctx_drv, NULL, &shared_secret_len);

            unsigned char* shared_secret_init = (unsigned char*)malloc(shared_secret_len);
            EVP_PKEY_derive(ctx_drv, shared_secret_init, &shared_secret_len);

            // hashing the shared secret to obtain the AES 256 key
            compute_sha256(shared_secret_init, shared_secret_len, AES_256_key);

            // reversing the shared secret init
            for (int i = 0; i < shared_secret_len/2; i++){
                unsigned char temp = shared_secret_init[i];
                shared_secret_init[i] = shared_secret_init[shared_secret_len - i - 1];
                shared_secret_init[shared_secret_len - i - 1] = temp;
            }

            // computing the hash of the shared secret
            compute_sha256(shared_secret_init, shared_secret_len, shared_secret);
            shared_secret_len = HASH_SIZE;
            free(shared_secret_init);

        } else if (strcmp(input, "help") == 0) {
            help();
        } else {
            printf("Invalid choice, please try again.\n");
        }
    }
    close(lissoc);
    return 0;
}