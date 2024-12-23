#include "messagelist.h"
#include "clientlist.h"

void sign_message(EVP_PKEY* rsa_priv_key, unsigned char* message, int message_len, unsigned char* signature, unsigned int* signature_len);

int lissoc = 0, connectsoc = 0, messagecount = 0;

int main(int argc, char** argv){

    if (argc != 2) {
        fprintf(stderr, "Invalid arguments!\nUsage: ./server <port>\n");
        exit(-1);
    }

    ClientList* clients = create_clientlist();
    MessageList messages = NULL;

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

    //hash the server private key to obtain the AES key
    unsigned char* rsa_priv_key_buf = NULL;
    int rsa_priv_key_len = i2d_PrivateKey(rsa_priv_key, &rsa_priv_key_buf);
    if (rsa_priv_key_len < 0) {
        perror("Failed to serialize RSA private key");
        return 1;
    }
    unsigned char srv_AES_256_key[HASH_SIZE];
    compute_sha256(rsa_priv_key_buf, rsa_priv_key_len, srv_AES_256_key);
    free(rsa_priv_key_buf);

    OpenSSL_add_all_algorithms();
    struct sockaddr_in srv_addr, server_addr;
    uint16_t port = (uint16_t)strtol(argv[1], NULL, 10);

    fd_set master;
    fd_set copy;
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

    FD_SET(0, &master);
    FD_SET(lissoc,&master);

    int fdmax;
    fdmax=lissoc;
    fflush(stdout);
    printf("Server entering main loop...\n");
    int selind;
    while(1){
        copy = master;
        select(fdmax+1, &copy, NULL, NULL, NULL);
        for(selind = 0; selind <= fdmax; selind++){
            if(FD_ISSET(selind, &copy)){
                if(selind == 0){
                    // commands from stdin
                }
                else if(selind == lissoc){ 
                    unsigned int len = sizeof(server_addr);
                    connectsoc = accept(lissoc, (struct sockaddr*) &server_addr, &len);
                    if(connectsoc == -1){
                        perror("accept error");
                        return -1;
                    }
                    FD_SET(connectsoc, &master);
                    printf("Client #%d connected\n", connectsoc);
                    if(connectsoc > fdmax) fdmax = connectsoc;
                }
                else{
                    char cmd[CMDLEN];
                    checkreturnint(recv(selind, (void*)&cmd, CMDLEN, 0), "recv hello error");
                    if(strcmp(cmd, "hello") == 0){
                        printf(YELLOW "Hello received from client #%d\n" RESET, selind);
                        printf("Client #%d starting handshake\n", selind);

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
                            return 1;
                        }
                        
                        // Deserialize the public key
                        EVP_PKEY* client_public_key = d2i_PUBKEY(NULL, (const unsigned char**)&pub_key_buf, pub_key_len);
                        if (!client_public_key) {
                            perror("Error deserializing public key");
                            return 1;
                        }

                        //serialize the public key
                        unsigned char* srv_pkey_buf = NULL;
                        int srv_pub_key_len = i2d_PUBKEY(server_keypair, &srv_pkey_buf);
                        if (srv_pub_key_len < 0) {
                            perror("Failed to serialize public key");
                        }

                        puts("sending public key to client");
                        // Send the length of the serialized public key buffer
                        uint32_t srv_pub_key_len_n = htonl(srv_pub_key_len);
                        checkreturnint(send(selind, (void*)&srv_pub_key_len_n, sizeof(uint32_t), 0), "Error sending public key length");
                        // Send the serialized public key to the server
                        checkreturnint(send(selind, (void*)srv_pkey_buf, srv_pub_key_len, 0), "Error sending public key");

                        // sign the public key
                        unsigned char* signature = (unsigned char*)malloc(EVP_PKEY_size(rsa_priv_key));
                        unsigned int signature_len;

                        // sign public key with function
                        sign_message(rsa_priv_key, srv_pkey_buf, srv_pub_key_len, signature, &signature_len);

                        puts("sending signature to client");
                        // send signature length to the client
                        uint32_t signature_len_n = htonl(signature_len);
                        checkreturnint(send(selind, (void*)&signature_len_n, sizeof(uint32_t), 0), "Error sending signature length");
                        // send the signature to the client
                        checkreturnint(send(selind, (void*)signature, signature_len, 0), "Error sending signature");

                        // Generate the shared secret
                        EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(server_keypair, NULL);
                        EVP_PKEY_derive_init(ctx_drv);
                        EVP_PKEY_derive_set_peer(ctx_drv, client_public_key);

                        size_t shared_secret_len;
                        EVP_PKEY_derive(ctx_drv, NULL, &shared_secret_len);

                        unsigned char* shared_secret_init = malloc(shared_secret_len);
                        EVP_PKEY_derive(ctx_drv, shared_secret_init, &shared_secret_len);

                        puts("shared secret init generated");
                        // generate the parameters for AES 256 CBC encryption
                        // computing SHA256 hash of the shared secret
                        unsigned char AES_256_key[HASH_SIZE];
                        compute_sha256(shared_secret_init, shared_secret_len, AES_256_key);

                        // reverse the shared secret
                        for (int i = 0; i < shared_secret_len / 2; i++){
                            unsigned char tmp = shared_secret_init[i];
                            shared_secret_init[i] = shared_secret_init[shared_secret_len - i - 1];
                            shared_secret_init[shared_secret_len - i - 1] = tmp;
                        }

                        //compute the hash of the shared secret
                        unsigned char shared_secret[HASH_SIZE];
                        compute_sha256(shared_secret_init, shared_secret_len, shared_secret);
                        shared_secret_len = HASH_SIZE;

                        // freeing DH parameters
                        free(shared_secret_init);
                        EVP_PKEY_CTX_free(ctx_drv);
                        EVP_PKEY_free(client_public_key);
                        OPENSSL_free(srv_pkey_buf);
                        OPENSSL_free(pub_key_str);
                        DH_free(dh);
                        EVP_PKEY_free(server_keypair);
                        EVP_PKEY_CTX_free(pkDHctx);
                        EVP_PKEY_free(dh_params);

                        // generate a random IV
                        unsigned char iv[IV_SIZE];
                        // send IV
                        iv_comm(selind, iv, shared_secret, shared_secret_len);
                        // generate a random nonce
                        RAND_poll();
                        unsigned char nonce[32];
                        memset(nonce, 0, 32);
                        RAND_bytes(nonce, 32);

                        unsigned char* enc_nonce = (unsigned char*)malloc(50);
                        int enc_nonce_len;
                        encrypt_message(nonce, 32, AES_256_key, iv, enc_nonce, &enc_nonce_len);

                        // send the encrypted nonce length to the client
                        uint32_t enc_nonce_len_n = htonl(enc_nonce_len);
                        checkreturnint(send(selind, (void*)&enc_nonce_len_n, sizeof(uint32_t), 0), "error sending encrypted nonce lenght");    
                        // send the encrypted nonce to the client
                        checkreturnint(send(selind, (void*)enc_nonce, enc_nonce_len, 0), "error sending encrypted nonce");

                        int nonce_len = 32;

                        // reverse the nonce
                        for (int i = 0; i <  nonce_len/ 2; i++){
                            unsigned char tmp = nonce[i];
                            nonce[i] = nonce[nonce_len - i - 1];
                            nonce[nonce_len - i - 1] = tmp;
                        }

                        // receive the IV from the client
                        unsigned char received_iv[IV_SIZE];
                        checkreturnint(recv(selind, (void*)received_iv, 16, 0), "error receiving IV");

                        // receive the encrypted structure length
                        uint32_t enc_struct_len_n;
                        checkreturnint(recv(selind, (void*)&enc_struct_len_n, sizeof(uint32_t), 0),"error receiving encrypted structure length");
                        uint32_t enc_struct_len = ntohl(enc_struct_len_n);
                        // receive the encrypted structure
                        unsigned char* enc_struct = (unsigned char*)malloc(enc_struct_len);
                        checkreturnint(recv(selind, (void*)enc_struct, enc_struct_len, 0), "error receiving encrypted structure");

                        // decrypt the structure
                        unsigned char* dec_struct = malloc(sizeof(TIMESTAMP_LEN + HMAC_SIZE));
                        int dec_struct_len;
                        decrypt_message(enc_struct, enc_struct_len, AES_256_key, received_iv, dec_struct, &dec_struct_len);
                        
                        MessageAuth recv_auth;
                        memcpy(&recv_auth, dec_struct, sizeof(recv_auth));
                        checktimestamp(recv_auth.timestamp);

                        // compute the HMAC of the nonce by using the function
                        unsigned char computed_hmac_nonce[HMAC_SIZE];
                        unsigned int computed_hmac_nonce_len;
                        compute_hmac(nonce, nonce_len, shared_secret, shared_secret_len, computed_hmac_nonce, &computed_hmac_nonce_len);

                        // compare the HMACs
                        if(CRYPTO_memcmp(computed_hmac_nonce, recv_auth.hmac, computed_hmac_nonce_len) == 0){
                            printf(GREEN "HMACs match, authentication complete\n" RESET);
                            // encrypt the shared secret with the AES key
                            unsigned char* enc_shared_secret = (unsigned char*)malloc(HASH_SIZE+16);
                            int enc_shared_secret_len;
                            encrypt_message_AES256ECB(shared_secret, HASH_SIZE, srv_AES_256_key, enc_shared_secret, &enc_shared_secret_len);
                            // encrypt the session key with the AES key
                            unsigned char* enc_session_key = (unsigned char*)malloc(HASH_SIZE+16);
                            int enc_session_key_len;
                            encrypt_message_AES256ECB(AES_256_key, HASH_SIZE, srv_AES_256_key, enc_session_key, &enc_session_key_len);
                            checkreturnint(addhs(clients, selind, enc_shared_secret, enc_shared_secret_len, enc_session_key, enc_session_key_len),"error adding client to the list");
                            free(enc_shared_secret);
                            free(enc_session_key);
                            // send ok to client
                            checkreturnint(send(selind, (void*)"ok", CMDLEN, 0), "error sending ok");
                        }
                        else{
                            printf(RED "HMACs do not match, connection aborted\n" RESET);
                            // send fail to client
                            checkreturnint(send(selind, (void*)"fail", CMDLEN, 0), "error sending fail");
                        }
                        free(enc_nonce);
                        free(signature);
                        free(enc_struct);
                        free(dec_struct);
                    }
                    else if (strcmp(cmd,"register")==0){
                        printf("Register request received, in else if\n");
                        ClientNode* current = findclient(clients, selind);
                        if(current->hs == 0){
                            printf(RED "Client #%d has not completed handshake\n" RESET, selind);
                            checkreturnint(send(selind, (void*)"nohs", CMDLEN, 0), "error sending nohs");
                            continue;
                        }
                        unsigned char shared_secret[AES_KEY_LEN];
                        unsigned char AES_256_key[AES_KEY_LEN];
                        int outlen;
                        decrypt_message_AES256ECB(current->sessionKey, current->sessionKeyLen, srv_AES_256_key, AES_256_key, &outlen);
                        decrypt_message_AES256ECB(current->sharedSecret, current->sharedSecretLen, srv_AES_256_key, shared_secret, &outlen);
                        int shared_secret_len = AES_KEY_LEN;
                        if(isloggedin(clients, getusername(clients, selind)) == 1){
                            printf(RED "User \"%s\" is already logged in.\n" RESET, getusername(clients, selind));
                            checkreturnint(send(selind, (void*)"already", CMDLEN, 0), "error sending already");
                            continue;
                        }
                        printf(YELLOW "Register request received\n" RESET);
                        unsigned char reg_iv[IV_SIZE];
                        receiveIVHMAC(selind, reg_iv, shared_secret, shared_secret_len);
                        // receiving concatenated reg message
                        uint32_t buflen_n;
                        checkreturnint(recv(selind, (void*)&buflen_n, sizeof(uint32_t), 0), "error receiving buflen");
                        long buflen = ntohl(buflen_n);
                        int ciphertext_len = buflen - HMAC_SIZE;
                        unsigned char* conc_buf = (unsigned char*)malloc(buflen);
                        unsigned char recv_hmac[HMAC_SIZE];
                        unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
                        checkreturnint(recv(selind, (void*) conc_buf, buflen, 0), "error receiving concatenated buffer");
                        split_hmac_ciphertext(conc_buf, recv_hmac, ciphertext, ciphertext_len);
                        free(conc_buf);

                        // compute HMAC of the ciphertext
                        unsigned char computed_hmac[HMAC_SIZE];
                        unsigned int computed_hmac_len;
                        compute_hmac(ciphertext, ciphertext_len, shared_secret, shared_secret_len, computed_hmac, &computed_hmac_len);

                        if(CRYPTO_memcmp(computed_hmac, recv_hmac, computed_hmac_len) != 0){
                            checkreturnint(send(selind, (void*)"fail", CMDLEN, 0), "error sending fail");
                            printf(RED "HMACs do not match, registration of user failed.\n" RESET);
                            continue;
                        }
                        else{
                            printf("HMACs match, registration validated.\n");
                        }
                        char plaintext [BUF_SIZE];
                        int plaintext_len;
                        decrypt_message(ciphertext, ciphertext_len, AES_256_key, reg_iv, (unsigned char*)plaintext, &plaintext_len);
                        char* email = strtok(plaintext, "/");
                        char* username = strtok(NULL, "/");
                        char* hashedpsw = strtok(NULL, "/");
                        char* recv_timestamp = strtok(NULL, "\0");

                        if(!email || !username || !hashedpsw || !recv_timestamp){
                            printf(RED "Invalid registration request\n" RESET);
                            checkreturnint(send(selind, (void*)"fail", CMDLEN, 0), "error sending fail");
                            continue;
                        }
                        printf("\n");
                        if(isin(clients, username) == 1){
                            printf(RED "User \"%s\" already registered.\n" RESET, username);
                            checkreturnint(send(selind, (void*)"exists", CMDLEN, 0), "error sending fail");
                            continue;
                        }
                        
                        if(checktimestamp(recv_timestamp) == 1){
                            checkreturnint(send(selind, (void*)"timeout", CMDLEN, 0), "error sending fail");
                            continue;
                        }
                        
                        // generate a nonce of 32 bytes
                        RAND_poll();
                        unsigned char challenge[32];
                        memset(challenge, 0, 32);
                        RAND_bytes(challenge, 32);
                        // write it in a file 
                        FILE* challengefile = fopen("challenge.txt", "w");
                        if(!challengefile){
                            perror("Failed to open challenge file");
                            exit(EXIT_FAILURE);
                        }
                        fwrite(challenge, 1, 32, challengefile);
                        fclose(challengefile);

                        puts("sending ok response to client");
                        checkreturnint(send(selind, (void*)"ok", CMDLEN, 0), "error sending ok");

                        // receive ready from client
                        char ready[CMDLEN];
                        checkreturnint(recv(selind, (void*)&ready, CMDLEN, 0), "error receiving ready");
                        if(strcmp(ready, "ready") != 0){
                            printf(RED "Client is not ready\n" RESET);
                            continue;
                        }

                        // read challenge hmac from file
                        unsigned char challenge_hmac[HMAC_SIZE];
                        FILE* challenge_hmac_file = fopen("chall_hmac.txt", "r");
                        if(!challenge_hmac_file){
                            perror("Failed to open challenge hmac file");
                            exit(EXIT_FAILURE);
                        }
                        fread(challenge_hmac, 1, HMAC_SIZE, challenge_hmac_file);
                        fclose(challenge_hmac_file);
                        remove("chall_hmac.txt");

                        // compute hmac over challenge to check if it matches the one received from the client
                        unsigned char computed_hmac_challenge[HMAC_SIZE];
                        unsigned int computed_hmac_challenge_len;
                        compute_hmac(challenge, 32, shared_secret, shared_secret_len, computed_hmac_challenge, &computed_hmac_challenge_len);

                        // compare the HMACs
                        if(CRYPTO_memcmp(computed_hmac_challenge, challenge_hmac, computed_hmac_challenge_len) == 0){
                            printf(GREEN "HMACs of challenge match, challenge completed\n" RESET);
                        }
                        else{
                            printf(RED "HMACs of challenge do not match, challenge failed\n" RESET);
                            checkreturnint(send(selind, (void*)"fail", CMDLEN, 0), "error sending fail");
                            checkreturnint(removeclient(clients, selind), "error removing client");
                            close(selind);
                            FD_CLR(selind, &master);
                            continue;
                        }

                        char* salt = malloc(SALT_LEN);
                        if (!RAND_bytes((unsigned char*) salt, SALT_LEN)) {
                            perror("RAND_bytes failed");
                            exit(EXIT_FAILURE);
                        }
                        unsigned char* salted_hashedpwd = malloc(HASH_SIZE);
                        compute_sha256_salted((unsigned char*)hashedpsw, strlen(hashedpsw),(char*)salted_hashedpwd, salt);
                        printf("salted_hashedpwd:\n");
                        for(int i = 0; i < HASH_SIZE; i++){
                            printf("%02x", salted_hashedpwd[i]);
                        }
                        printf("\n");
                        checkreturnint(addinfo(clients, selind, username, email, (char*)salted_hashedpwd, salt), "addinfo error");
                        free(ciphertext);
                        free(salt);
                        free(salted_hashedpwd);
                    } 
                    else if (strcmp(cmd, "login") == 0) {
                        printf(YELLOW "Login request received\n" RESET);
                        ClientNode* current = findclient(clients, selind);
                        if(current->hs == 0){
                            printf(RED "Client #%d has not completed handshake\n" RESET, selind);
                            checkreturnint(send(selind, (void*)"nohs", CMDLEN, 0), "error sending nohs");
                            continue;
                        }
                        unsigned char shared_secret[AES_KEY_LEN];
                        unsigned char AES_256_key[AES_KEY_LEN];
                        int outlen;
                        decrypt_message_AES256ECB(current->sessionKey, current->sessionKeyLen, srv_AES_256_key, AES_256_key, &outlen);
                        decrypt_message_AES256ECB(current->sharedSecret, current->sharedSecretLen, srv_AES_256_key, shared_secret, &outlen);
                        int shared_secret_len = AES_KEY_LEN;
                        unsigned char* login_iv = (unsigned char*)malloc(IV_SIZE);
                        receiveIVHMAC(selind, login_iv, shared_secret, shared_secret_len);
                        // receiving ciphertext
                        uint32_t buflen_n;
                        checkreturnint(recv(selind, (void*)&buflen_n, sizeof(uint32_t), 0), "error receiving buflen");
                        long buflen = ntohl(buflen_n);
                        int ciphertext_len = buflen - HMAC_SIZE;
                        unsigned char* conc_buf = (unsigned char*)malloc(buflen);
                        unsigned char recv_hmac[HMAC_SIZE];
                        unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
                        checkreturnint(recv(selind, (void*) conc_buf, buflen, 0), "error receiving concatenated buffer");
                        split_hmac_ciphertext(conc_buf, recv_hmac, ciphertext, ciphertext_len);
                        free(conc_buf);

                        // compute HMAC of the ciphertext
                        unsigned char* computed_hmac[HMAC_SIZE];
                        unsigned int computed_hmac_len;
                        compute_hmac(ciphertext, ciphertext_len, shared_secret, shared_secret_len, (unsigned char*)computed_hmac, &computed_hmac_len);
                        
                        if(CRYPTO_memcmp(computed_hmac, recv_hmac, computed_hmac_len) != 0){
                            checkreturnint(send(selind, (void*)"fail", CMDLEN, 0), "error sending fail");
                            printf("HMACs do not match, login failed.\n");
                            continue;
                        }
                        else{
                            printf("HMACs match, login validated\n");
                        }

                        char* plaintext = malloc(BUF_SIZE);
                        int plaintext_len;
                        decrypt_message(ciphertext, ciphertext_len, AES_256_key, login_iv, (unsigned char*)plaintext, &plaintext_len);

                        char* username = strtok(plaintext, "/");
                        char* hashedpsw = strtok(NULL, "/");
                        char* recv_timestamp = strtok(NULL, "\0");
                        if(!username || !hashedpsw || !recv_timestamp){
                            printf("Invalid login request\n");
                            checkreturnint(send(selind, (void*)"fail", CMDLEN, 0), "error sending fail");
                            continue;
                        }

                        if(isloggedin(clients, username) == 1){
                            printf(RED "User \"%s\" is already logged in.\n" RESET, username);
                            checkreturnint(send(selind, (void*)"already", CMDLEN, 0), "error sending already");
                            continue;
                        }

                        if(isin(clients, username) < 0){
                            printf("User \"%s\" not registered.\n", username);
                            checkreturnint(send(selind, (void*)"nouser", CMDLEN, 0), "error sending fail");
                            continue;
                        }

                        if(checkpwd(current, (unsigned char*)hashedpsw) == 1){
                            printf(RED "Password for user \"%s\" is incorrect.\n" RESET, username);
                            checkreturnint(send(selind, (void*)"wrongpsw", CMDLEN, 0), "error sending fail");
                            continue;
                        }

                        if(checktimestamp(recv_timestamp) == 1){
                            checkreturnint(send(selind, (void*)"timeout", CMDLEN, 0), "error sending fail");
                            continue;
                        }
                        
                        // making user status = 1 = online
                        changestatus(clients, username, 1);
                        puts("sending ok response to client");
                        checkreturnint(send(selind, (void*)"ok", CMDLEN, 0), "error sending ok");
                        free(login_iv);
                        free(ciphertext);
                        free(plaintext);
                        continue;
                    } else if (strcmp(cmd, "list") == 0) {
                        printf(YELLOW "List request received\n" RESET);
                        if(isloggedin(clients, getusername(clients, selind)) == 0){
                            checkreturnint(send(selind, (void*)"notlogged", CMDLEN, 0), "error sending notlogged");
                            continue;
                        }
                        ClientNode* current = findclient(clients, selind);
                        unsigned char shared_secret[AES_KEY_LEN];
                        unsigned char AES_256_key[AES_KEY_LEN];
                        int outlen;
                        decrypt_message_AES256ECB(current->sessionKey, current->sessionKeyLen, srv_AES_256_key, AES_256_key, &outlen);
                        decrypt_message_AES256ECB(current->sharedSecret, current->sharedSecretLen, srv_AES_256_key, shared_secret, &outlen);
                        int shared_secret_len = AES_KEY_LEN;

                        // receive IV
                        unsigned char* list_iv = (unsigned char*)malloc(IV_SIZE);
                        receiveIVHMAC(selind, list_iv, shared_secret, shared_secret_len);

                        // receive ciphertext length & ciphertext
                        uint32_t buflen_n;
                        checkreturnint(recv(selind, (void*)&buflen_n, sizeof(uint32_t), 0), "error receiving buflen");
                        long buflen = ntohl(buflen_n);
                        int ciphertext_len = buflen - HMAC_SIZE;
                        unsigned char* conc_buf = (unsigned char*)malloc(buflen);
                        unsigned char recv_hmac[HMAC_SIZE];
                        unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
                        checkreturnint(recv(selind, (void*) conc_buf, buflen, 0), "error receiving concatenated buffer");
                        split_hmac_ciphertext(conc_buf, recv_hmac, ciphertext, ciphertext_len);
                        free(conc_buf);

                        // compute HMAC of the ciphertext
                        unsigned char computed_hmac[HMAC_SIZE];
                        unsigned int computed_hmac_len;
                        compute_hmac(ciphertext, ciphertext_len, shared_secret, shared_secret_len, computed_hmac, &computed_hmac_len);

                        if(CRYPTO_memcmp(computed_hmac, recv_hmac, computed_hmac_len) != 0){
                            checkreturnint(send(selind, (void*)"fail", CMDLEN, 0), "error sending fail");
                            printf("HMACs do not match, list failed.\n");
                            continue;
                        }
                        else{
                            printf("HMACs match, list validated\n");
                        }

                        // decrypt the ciphertext
                        char* plaintext = malloc(4 + 28 + 3);
                        int plaintext_len;
                        decrypt_message(ciphertext, ciphertext_len, AES_256_key, list_iv, (unsigned char*)plaintext, &plaintext_len);
                        
                        int n = atoi(strtok(plaintext, "/"));
                        char* list_timestamp = strtok(NULL, "\0");

                        if(checktimestamp(list_timestamp) == 1){
                            checkreturnint(send(selind, (void*)"timeout", CMDLEN, 0), "error sending fail");
                            continue;
                        }

                        if(isloggedin(clients, getusername(clients, selind)) == 0){
                            checkreturnint(send(selind, (void*)"notlogged", CMDLEN, 0), "error sending notlogged");
                            continue;
                        }

                        // check if the message list is empty
                        if(messages == NULL){
                            checkreturnint(send(selind, (void*)"empty", CMDLEN, 0), "error sending empty");
                            continue;
                        }
                        
                        checkreturnint(send(selind, (void*)"ok", CMDLEN, 0), "error sending ok");
                        iv_comm(selind, list_iv, shared_secret, shared_secret_len);

                        char buffer[BUF_SIZE];
                        get_last_n_messages(messages, n, buffer, BUF_SIZE, srv_AES_256_key);
                        // concatenate the buffer with the timestamp
                        char* timestamp = create_timestamp();
                        size_t timestamp_len = strlen(timestamp);
                        size_t buffer_len = strlen(buffer);
                        size_t new_buffer_len = buffer_len + 1 + timestamp_len;
                        char new_buffer[new_buffer_len + 1];
                        memcpy(new_buffer, buffer, buffer_len);
                        new_buffer[buffer_len] = '/';
                        memcpy(new_buffer + buffer_len + 1, timestamp, timestamp_len);
                        new_buffer[new_buffer_len] = '\0';
                        free(timestamp);

                        unsigned char* enc_buffer = (unsigned char*)malloc((BUF_SIZE+28)*n+16);
                        int enc_buffer_len;
                        // encrypting buffer with AES CBC to send it to client
                        encrypt_message((unsigned char*)new_buffer, new_buffer_len, AES_256_key, list_iv, enc_buffer, &enc_buffer_len);
                        unsigned char encbuffer_hmac[HMAC_SIZE];
                        unsigned int encbuffer_hmac_len;
                        compute_hmac(enc_buffer, enc_buffer_len, shared_secret, shared_secret_len, encbuffer_hmac, &encbuffer_hmac_len);
                        long sendlen = HMAC_SIZE + enc_buffer_len;
                        uint32_t sendlen_n = htonl(sendlen);
                        unsigned char sendbuf[sendlen];
                        concatenate_hmac_ciphertext(encbuffer_hmac, enc_buffer, enc_buffer_len, sendbuf);

                        checkreturnint(send(selind, (void*)&sendlen_n, sizeof(uint32_t), 0), "error sending sendlen");
                        checkreturnint(send(selind, sendbuf, sendlen, 0), "error sending sendbuf");
                        
                        free(ciphertext);
                        free(list_iv);
                        free(enc_buffer);
                        free(plaintext);
                        continue;
                    } else if (strcmp(cmd, "get") == 0) {
                        printf(YELLOW "Get request received\n" RESET);
                        if(isloggedin(clients, getusername(clients, selind)) == 0){
                            checkreturnint(send(selind, (void*)"notlogged", CMDLEN, 0), "error sending notlogged");
                            continue;
                        }
                        
                        ClientNode* current = findclient(clients, selind);
                        unsigned char shared_secret[AES_KEY_LEN];
                        unsigned char AES_256_key[AES_KEY_LEN];
                        int outlen;
                        decrypt_message_AES256ECB(current->sessionKey, current->sessionKeyLen, srv_AES_256_key, AES_256_key, &outlen);
                        decrypt_message_AES256ECB(current->sharedSecret, current->sharedSecretLen, srv_AES_256_key, shared_secret, &outlen);
                        int shared_secret_len = AES_KEY_LEN;

                        // receive IV
                        unsigned char* get_iv[IV_SIZE];
                        receiveIVHMAC(selind, (unsigned char*)get_iv, shared_secret, shared_secret_len);

                        // receive ciphertext length & ciphertext
                        uint32_t buflen_n;
                        checkreturnint(recv(selind, (void*)&buflen_n, sizeof(uint32_t), 0), "error receiving buflen");
                        long buflen = ntohl(buflen_n);
                        int ciphertext_len = buflen - HMAC_SIZE;
                        unsigned char* conc_buf = (unsigned char*)malloc(buflen);
                        unsigned char recv_hmac[HMAC_SIZE];
                        unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
                        checkreturnint(recv(selind, (void*) conc_buf, buflen, 0), "error receiving concatenated buffer");
                        split_hmac_ciphertext(conc_buf, recv_hmac, ciphertext, ciphertext_len);
                        free(conc_buf);

                        // compute HMAC of the ciphertext
                        unsigned char computed_hmac[HMAC_SIZE];
                        unsigned int computed_hmac_len;
                        compute_hmac(ciphertext, ciphertext_len, shared_secret, shared_secret_len, computed_hmac, &computed_hmac_len);

                        if(CRYPTO_memcmp(computed_hmac, recv_hmac, computed_hmac_len) != 0){
                            checkreturnint(send(selind, (void*)"fail", CMDLEN, 0), "error sending fail");
                            printf("HMACs do not match, get failed.\n");
                            continue;
                        }
                        else{
                            printf("HMACs match, get validated\n");
                        }

                        // decrypt the ciphertext
                        char* plaintext = malloc(4 + 28 + 3);
                        int plaintext_len;
                        decrypt_message(ciphertext, ciphertext_len, AES_256_key, (unsigned char*)get_iv, (unsigned char*)plaintext, &plaintext_len);
                        free(ciphertext);

                        int mid = atoi(strtok(plaintext, "/"));
                        char* get_timestamp = strtok(NULL, "\0");

                        if(checktimestamp(get_timestamp) == 1){
                            checkreturnint(send(selind, (void*)"timeout", CMDLEN, 0), "error sending fail");
                            continue;
                        }

                        if(isloggedin(clients, getusername(clients, selind)) == 0){
                            checkreturnint(send(selind, (void*)"notlogged", CMDLEN, 0), "error sending notlogged");
                            continue;
                        }

                        checkreturnint(send(selind, (void*)"ok", CMDLEN, 0), "error sending ok");

                        unsigned char* iv[IV_SIZE];
                        iv_comm(selind, (unsigned char*)iv, shared_secret, shared_secret_len);

                        char buffer[BUF_SIZE];
                        getmessage(messages, mid, buffer, BUF_SIZE, srv_AES_256_key);

                        // concatenate the buffer with the timestamp
                        char* timestamp = create_timestamp();
                        size_t timestamp_len = strlen(timestamp);
                        size_t buffer_len = strlen(buffer);
                        size_t new_buffer_len = buffer_len + 1 + timestamp_len;
                        char new_buffer[new_buffer_len + 1];
                        memcpy(new_buffer, buffer, buffer_len);
                        new_buffer[buffer_len] = '/';
                        memcpy(new_buffer + buffer_len + 1, timestamp, timestamp_len);
                        new_buffer[new_buffer_len] = '\0';
                        free(timestamp);

                        unsigned char* enc_buffer = (unsigned char*)malloc(BUF_SIZE+16);
                        int enc_buffer_len;
                        // encrypting buffer with AES CBC to send it to client
                        encrypt_message((unsigned char*)new_buffer, new_buffer_len, AES_256_key, (unsigned char*)iv, enc_buffer, &enc_buffer_len);
                        unsigned char encbuffer_hmac[HMAC_SIZE];
                        unsigned int encbuffer_hmac_len;
                        compute_hmac(enc_buffer, enc_buffer_len, shared_secret, shared_secret_len, encbuffer_hmac, &encbuffer_hmac_len);
                        long sendlen = HMAC_SIZE + enc_buffer_len;
                        uint32_t sendlen_n = htonl(sendlen);
                        unsigned char sendbuf[sendlen];
                        concatenate_hmac_ciphertext(encbuffer_hmac, enc_buffer, enc_buffer_len, sendbuf);

                        checkreturnint(send(selind, (void*)&sendlen_n, sizeof(uint32_t), 0), "error sending sendlen");
                        checkreturnint(send(selind, sendbuf, sendlen, 0), "error sending sendbuf");
                        free(enc_buffer);
                        free(plaintext);
                        continue;
                    } else if (strcmp(cmd, "add") == 0) {
                        printf(YELLOW "Add request received\n" RESET);
                        ClientNode* current = findclient(clients, selind);
                        if(current->hs == 0){
                            printf(RED "Client #%d has not completed handshake\n" RESET, selind);
                            checkreturnint(send(selind, (void*)"nohs", CMDLEN, 0), "error sending nohs");
                            continue;
                        }
                        unsigned char shared_secret[AES_KEY_LEN];
                        unsigned char AES_256_key[AES_KEY_LEN];
                        int outlen;
                        decrypt_message_AES256ECB(current->sessionKey, current->sessionKeyLen, srv_AES_256_key, AES_256_key, &outlen);
                        decrypt_message_AES256ECB(current->sharedSecret, current->sharedSecretLen, srv_AES_256_key, shared_secret, &outlen);
                        int shared_secret_len = AES_KEY_LEN;

                        unsigned char add_iv [IV_SIZE];
                        receiveIVHMAC(selind, add_iv, shared_secret, shared_secret_len);

                        // receiving ciphertext
                        uint32_t buflen_n;
                        checkreturnint(recv(selind, (void*)&buflen_n, sizeof(uint32_t), 0), "error receiving buflen");
                        long buflen = ntohl(buflen_n);
                        int ciphertext_len = buflen - HMAC_SIZE;
                        unsigned char* conc_buf = (unsigned char*)malloc(buflen);
                        unsigned char recv_hmac[HMAC_SIZE];
                        unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
                        checkreturnint(recv(selind, (void*) conc_buf, buflen, 0), "error receiving concatenated buffer");
                        split_hmac_ciphertext(conc_buf, recv_hmac, ciphertext, ciphertext_len);
                        free(conc_buf);
                        
                        // compute HMAC of the ciphertext
                        unsigned char computed_hmac[HMAC_SIZE];
                        unsigned int computed_hmac_len;
                        compute_hmac(ciphertext, ciphertext_len, shared_secret, shared_secret_len, computed_hmac, &computed_hmac_len);

                        if(CRYPTO_memcmp(computed_hmac, recv_hmac, computed_hmac_len) != 0){
                            checkreturnint(send(selind, (void*)"fail", CMDLEN, 0), "error sending fail");
                            printf("HMACs do not match, add failed.\n");
                            continue;
                        }
                        else{
                            printf("HMACs match, add validated\n");
                        }

                        if(isloggedin(clients, getusername(clients, selind)) == 0){
                            puts("sending notlogged response to client");
                            checkreturnint(send(selind, (void*)"notlogged", CMDLEN, 0), "error sending notlogged");
                            continue;
                        }
                        else{
                            puts("sending ok response to client");
                            checkreturnint(send(selind, (void*)"ok", CMDLEN, 0), "error sending ok");
                        }

                        char* plaintext = malloc(BUF_SIZE);
                        int plaintext_len;
                        decrypt_message(ciphertext, ciphertext_len, AES_256_key, add_iv, (unsigned char*)plaintext, &plaintext_len);

                        char* title = strtok(plaintext, "/");
                        char* body = strtok(NULL, "\0");

                        char enc_body[BODY_LEN];
                        int enc_body_len;
                        encrypt_message_AES256ECB((unsigned char*)body, strlen(body)+1, srv_AES_256_key, (unsigned char*)enc_body, &enc_body_len);

                        Message* message = create_message(messagecount, current->username, title, enc_body, enc_body_len);
                        
                        insert_message(&messages, message);
                        messagecount++;
                        puts("list after add:");
                        print_messagelist(messages);

                        free(ciphertext);
                        free(plaintext);
                        continue;
                    } else if (strcmp (cmd, "logout") == 0) {
                        printf(YELLOW "Logout request received\n" RESET);
                        ClientNode* current = findclient(clients, selind);
                        if(current->hs == 0){
                            printf(RED "Client #%d has not completed handshake\n" RESET, selind);
                            checkreturnint(send(selind, (void*)"nohs", CMDLEN, 0), "error sending nohs");
                            continue;
                        }

                        // send ok response to client
                        checkreturnint(send(selind, (void*)"ok", CMDLEN, 0), "error sending ok");

                        // put user status to 0 = offline
                        changestatus(clients, getusername(clients, selind), 0);

                        // generate new DH parameters
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

                        // Deserialize the public key
                        EVP_PKEY* client_public_key = d2i_PUBKEY(NULL, (const unsigned char**)&pub_key_buf, pub_key_len);
                        if (!client_public_key) {
                            perror("Error deserializing public key");
                            free(pub_key_buf);
                            return 1;
                        }

                        //serialize the public key
                        unsigned char* srv_pkey_buf = NULL;
                        int srv_pub_key_len = i2d_PUBKEY(server_keypair, &srv_pkey_buf);
                        if (srv_pub_key_len < 0) {
                            perror("Failed to serialize public key");
                        }

                        // Send the length of the serialized public key buffer
                        uint32_t srv_pub_key_len_n = htonl(srv_pub_key_len);
                        checkreturnint(send(selind, (void*)&srv_pub_key_len_n, sizeof(uint32_t), 0), "Error sending public key length");
        
                        // Send the serialized public key to the server
                        checkreturnint(send(selind, (void*)srv_pkey_buf, srv_pub_key_len, 0), "Error sending public key");

                        // sign the public key
                        unsigned char* signature;
                        unsigned int signature_len;
                        signature = (unsigned char*)malloc(EVP_PKEY_size(rsa_priv_key));

                        // sign public key with function
                        sign_message(rsa_priv_key, srv_pkey_buf, srv_pub_key_len, signature, &signature_len);

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

                        current->hs = 1;
                        unsigned char* AES_256_key;
                        AES_256_key = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
                        compute_sha256(shared_secret, shared_secret_len, AES_256_key);
                        // reverse the shared secret
                        for (int i = 0; i < shared_secret_len / 2; i++){
                            unsigned char tmp = shared_secret[i];
                            shared_secret[i] = shared_secret[shared_secret_len - i - 1];
                            shared_secret[shared_secret_len - i - 1] = tmp;
                        }

                        unsigned char* shared_secret_hash = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
                        compute_sha256(shared_secret, shared_secret_len, shared_secret_hash);

                        shared_secret_len = HASH_SIZE;

                        encrypt_message_AES256ECB(shared_secret_hash, shared_secret_len, srv_AES_256_key, current->sharedSecret, &current->sharedSecretLen);
                        encrypt_message_AES256ECB(AES_256_key, AES_KEY_LEN, srv_AES_256_key, current->sessionKey, &current->sessionKeyLen);
                        printlist(clients);

                        // freeing dh parameters
                        free(shared_secret_hash);
                        free(AES_256_key);
                        free(signature);
                        EVP_PKEY_CTX_free(ctx_drv);
                        EVP_PKEY_free(client_public_key);
                        OPENSSL_free(srv_pkey_buf);
                        OPENSSL_free(pub_key_str);
                        DH_free(dh);
                        EVP_PKEY_free(server_keypair);
                        EVP_PKEY_CTX_free(pkDHctx);
                        EVP_PKEY_free(dh_params);
                    } else {
                        printf(RED "Client #%d quitted.\n" RESET, selind);
                        checkreturnint(removeclient(clients, selind), "error removing client");
                        close(selind);
                        FD_CLR(selind, &master);
                        continue;
                    }
                }
            }
        }
    }
    free_clientlist(clients);
    free_messagelist(messages);
}
    
// function to generate a message signature using the server private key
void sign_message(EVP_PKEY* rsa_priv_key , unsigned char* message, int message_len, unsigned char* signature, unsigned int* signature_len){
    EVP_MD_CTX* sign_ctx;
    sign_ctx = EVP_MD_CTX_new();
    EVP_SignInit(sign_ctx, EVP_sha256());
    EVP_SignUpdate(sign_ctx, message, message_len);
    EVP_SignFinal(sign_ctx, signature, signature_len, rsa_priv_key);
    EVP_MD_CTX_free(sign_ctx);
}