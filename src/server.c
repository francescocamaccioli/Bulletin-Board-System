#include "messagelist.h"
#include "clientlist.h"

int lissoc = 0, connectsoc = 0, messagecount = 0;


// function to generate a message signature using the server private key
void sign_message(EVP_PKEY* rsa_priv_key , unsigned char* message, int message_len, unsigned char* signature, unsigned int* signature_len){
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

    ClientList* clients = create_clientlist();
    MessageList* messages = NULL;

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

    //hash the server private key to obtain the AES key
    unsigned char* rsa_priv_key_buf = NULL;
    int rsa_priv_key_len = i2d_PrivateKey(rsa_priv_key, &rsa_priv_key_buf);
    if (rsa_priv_key_len < 0) {
        perror("Failed to serialize RSA private key");
        return 1;
    }
    unsigned char* srv_AES_256_key;
    srv_AES_256_key = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    compute_sha256(rsa_priv_key_buf, rsa_priv_key_len, srv_AES_256_key);
    free(rsa_priv_key_buf);

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
                    unsigned int len = sizeof(server_addr);
                    connectsoc = accept(lissoc, (struct sockaddr*) &server_addr, &len);
                    if(connectsoc == -1){
                        perror("accept error");
                        return -1;
                    }
                    FD_SET(connectsoc, &master); //Inserisco nuovo socket in fd_set master
                    printf("Client #%d connected\n", connectsoc);
                    if(connectsoc > fdmax) fdmax = connectsoc;
                }
                else{
                    //Operazione sul socket di connessione
                    //Qua faccio uno switch per verificare quale tipologia di dispositivo è. In questo modo posso differenziare le operazioni. Per fare ciò recupero le informazioni dal file
                    //Delle connessioni attive.
                    printf(YELLOW " request from client #%d...\n" RESET, selind);
                    char cmd[CMDLEN];
                    checkreturnint(recv(selind, (void*)&cmd, CMDLEN, 0), "recv hello error");     
                    if(strcmp(cmd, "hello") == 0){
                        printf("Client #%d starting handshake\n", selind);
                    
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

                        printf("Certificate sent to client #%d\n", selind);

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
                        //printf("public key received from client\n");
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

                        //printf("public key length sent to server\n");
                        fflush(stdout);
        
                        // Send the serialized public key to the server
                        checkreturnint(send(selind, (void*)srv_pkey_buf, srv_pub_key_len, 0), "Error sending public key");

                        //printf("public key sent to client\n");
                        fflush(stdout);
                        
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
                        free(signature);

                        // Generate the shared secret
                        EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(server_keypair, NULL);
                        EVP_PKEY_derive_init(ctx_drv);
                        EVP_PKEY_derive_set_peer(ctx_drv, client_public_key);
                        unsigned char* shared_secret;

                        size_t shared_secret_len;
                        EVP_PKEY_derive(ctx_drv, NULL, &shared_secret_len);
                        //printf("Shared secret length: %ld\n", shared_secret_len);

                        shared_secret = (unsigned char*)malloc(shared_secret_len);
                        EVP_PKEY_derive(ctx_drv, shared_secret, &shared_secret_len);

                        // Print the shared secret
                        /* printf("Shared secret: \n");
                        for (int i = 0; i < shared_secret_len; i++) {
                            printf("%02x", shared_secret[i]);
                        }
                        printf("\n"); */
                        // generate the parameters for AES 256 CBC encryption
                        // computing SHA256 hash of the shared secret
                        unsigned char* AES_256_key;
                        EVP_MD_CTX* keyctx;
                        AES_256_key = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
                        compute_sha256(shared_secret, shared_secret_len, AES_256_key);

                        // print the AES 256 key
                    /*  printf("AES 256 key: \n");
                        for (int i = 0; i < AES_256_key_len; i++){
                            printf("%02x", AES_256_key[i]);
                        }
                        printf("\n"); */


                        // generate a random IV
                        unsigned char* iv = (unsigned char*)malloc(IV_SIZE);
                        // send IV
                        iv_comm(selind, iv, shared_secret, shared_secret_len);
                        // generate a random nonce
                        RAND_poll();
                        unsigned char nonce[32];
                        memset(nonce, 0, 32);
                        RAND_bytes(nonce, 32);

                        // print the nonce
                        /* printf("Nonce: ");
                        for (int i = 0; i < 32; i++){
                            printf("%02x", nonce[i]);
                        }
                        printf("\n"); */

                        // encrypt the nonce with AES 256 CBC
                        /* printf("AES 256 key: \n");
                        for (int i = 0; i < AES_256_key_len; i++){
                            printf("%02x", AES_256_key[i]);
                        }
                        printf("\n");
                        printf("IV: \n");
                        for (int i = 0; i < 16; i++){
                            printf("%02x", iv[i]);
                        } */
                        unsigned char* enc_nonce = (unsigned char*)malloc(50);
                        int enc_nonce_len;
                        encrypt_message(nonce, 32, AES_256_key, iv, enc_nonce, &enc_nonce_len);
                        free(iv);
                        // print the encrypted nonce
                        /* printf("Encrypted nonce: ");
                        for (int i = 0; i < enc_nonce_len; i++){
                            printf("%02x", enc_nonce[i]);
                        }
                        printf("\n");
        */

                        // send the encrypted nonce length to the client
                        uint32_t enc_nonce_len_n = htonl(enc_nonce_len);
                        checkreturnint(send(selind, (void*)&enc_nonce_len_n, sizeof(uint32_t), 0), "error sending encrypted nonce lenght");
                        //printf("encrypted nonce length sent\n");
                        
                        // send the encrypted nonce to the client
                        checkreturnint(send(selind, (void*)enc_nonce, enc_nonce_len, 0), "error sending encrypted nonce");
                        //printf("encrypted nonce sent\n");
                        free(enc_nonce);

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
    /*                     printf("Received IV: ");
                        for (int i = 0; i < 16; i++){
                            printf("%02x", received_iv[i]);
                        }
                        printf("\n"); */

                        // receive the encrypted structure length
                        uint32_t enc_struct_len_n;
                        checkreturnint(recv(selind, (void*)&enc_struct_len_n, sizeof(uint32_t), 0),"error receiving encrypted structure length");
                        uint32_t enc_struct_len = ntohl(enc_struct_len_n);
                        // receive the encrypted structure
                        unsigned char* enc_struct;
                        enc_struct = (unsigned char*)malloc(enc_struct_len);
                        checkreturnint(recv(selind, (void*)enc_struct, enc_struct_len, 0), "error receiving encrypted structure");

                        // decrypt the structure
                        unsigned char* dec_struct = malloc(sizeof(TIMESTAMP_LEN + HMAC_SIZE));
                        int dec_struct_len;
                        decrypt_message(enc_struct, enc_struct_len, AES_256_key, received_iv, dec_struct, &dec_struct_len);
                        
                        // free(received_iv);
                        
                        MessageAuth recv_auth;
                        memcpy(&recv_auth, dec_struct, sizeof(recv_auth));

                        // print the decrypted structure
                        /* printf("Decrypted structure: \n");
                        printf("Timestamp: %s\n", recv_auth.ts);
                        printf("Received HMAC: ");
                        for (int i = 0; i < EVP_MD_size(EVP_sha256()); i++){
                            printf("%02x", recv_auth.hmac[i]);
                        }
                        printf("\n"); */

                        checktimestamp(recv_auth.timestamp);

                        // compute the HMAC of the nonce by using the function
                        unsigned char* computed_hmac_nonce;
                        unsigned int computed_hmac_nonce_len;
                        computed_hmac_nonce = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
                        /* printf("Nonce: ");
                        for (int i = 0; i < nonce_len; i++){
                            printf("%02x", nonce[i]);
                        } */
                        compute_hmac(nonce, nonce_len, shared_secret, shared_secret_len, computed_hmac_nonce, &computed_hmac_nonce_len);
                        /* printf("Computed HMAC of the nonce: ");
                        for (int i = 0; i < computed_hmac_nonce_len; i++){
                            printf("%02x", computed_hmac_nonce[i]);
                        }
                        printf("\n"); */

                        // compare the HMACs
                        if(CRYPTO_memcmp(computed_hmac_nonce, recv_auth.hmac, computed_hmac_nonce_len) == 0){
                            printf(GREEN "HMACs match, authentication complete\n" RESET);
                            checkreturnint(addhs(clients, selind, shared_secret, AES_256_key),"error adding client to the list");
                            printlist(clients);

                        }
                        else{
                            printf(RED "HMACs do not match, connection aborted\n" RESET);
                        }
                        free(received_iv);
                        free(enc_struct);
                        free(dec_struct);
                        free(computed_hmac_nonce);
                    }
                    else if (strcmp(cmd,"register")==0){
                    //checkreturnint(recv(selind, (void*)&cmd, CMDLEN, 0), "recv of command error");
                        printf("Register request received, in else if\n");
                        ClientNode* current = findclient(clients, selind);
                        if(current->hs == 0){
                            printf(RED "Client #%d has not completed handshake\n" RESET, selind);
                            checkreturnint(send(selind, (void*)"nohs", CMDLEN, 0), "error sending nohs");
                            continue;
                        }
                        unsigned char shared_secret[SHARED_SECRET_LEN];
                        unsigned char AES_256_key[AES_KEY_LEN];
                        memcpy(shared_secret, current->sharedSecret, SHARED_SECRET_LEN);
                        memcpy(AES_256_key, current->sessionKey, AES_KEY_LEN);
                        int shared_secret_len = SHARED_SECRET_LEN;
                        if(isloggedin(clients, getusername(clients, selind)) == 1){
                            printf(RED "User \"%s\" is already logged in.\n" RESET, getusername(clients, selind));
                            checkreturnint(send(selind, (void*)"already", CMDLEN, 0), "error sending already");
                            continue;
                        }
                        printf(YELLOW "Register request received\n" RESET);
                        unsigned char* reg_iv = (unsigned char*)malloc(IV_SIZE);
                        receiveIVHMAC(selind, reg_iv, shared_secret, shared_secret_len);
                        // receiving ciphertext
                        uint32_t ciphertext_len_n;
                        checkreturnint(recv(selind, (void*)&ciphertext_len_n, sizeof(uint32_t), 0), "error receiving ct len");
                        long ciphertext_len = ntohl(ciphertext_len_n);
                        unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
                        checkreturnint(recv(selind, (void*) ciphertext, ciphertext_len, 0), "error receiving ct");

                        // receive HMAC length
                        uint32_t hmac_len_n;
                        checkreturnint(recv(selind, (void*)&hmac_len_n, sizeof(uint32_t), 0), "error receiving HMAC length");
                        long hmac_len = ntohl(hmac_len_n);
                        unsigned char* recv_hmac = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
                        checkreturnint(recv(selind, (void*)recv_hmac, hmac_len, 0), "error receiving HMAC");

                        // compute HMAC of the ciphertext
                        unsigned char* computed_hmac;
                        unsigned int computed_hmac_len;
                        computed_hmac = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
                        compute_hmac(ciphertext, ciphertext_len, shared_secret, shared_secret_len, computed_hmac, &computed_hmac_len);

                        if(CRYPTO_memcmp(computed_hmac, recv_hmac, computed_hmac_len) != 0){
                            checkreturnint(send(selind, (void*)"fail", CMDLEN, 0), "error sending fail");
                            printf(RED "HMACs do not match, registration of user failed.\n" RESET);
                            continue;
                        }
                        else{
                            printf("HMACs match, registration validated.\n");
                        }
                        free(computed_hmac);
                        free(recv_hmac);

                        char* plaintext = malloc(BUF_SIZE);
                        int plaintext_len;
                        decrypt_message(ciphertext, ciphertext_len, AES_256_key, reg_iv, (unsigned char*)plaintext, &plaintext_len);
                        char* email = strtok(plaintext, ",");
                        char* username = strtok(NULL, ",");
                        char* hashedpsw = strtok(NULL, ",");
                        char* recv_timestamp = strtok(NULL, "\0");

                        if(!email || !username || !hashedpsw || !recv_timestamp){
                            printf(RED "Invalid registration request\n" RESET);
                            checkreturnint(send(selind, (void*)"fail", CMDLEN, 0), "error sending fail");
                            continue;
                        }
                        
                        if(isin(clients, username) == 1){
                            printf(RED "User \"%s\" already registered.\n" RESET, username);
                            checkreturnint(send(selind, (void*)"exists", CMDLEN, 0), "error sending fail");
                            continue;
                        }

                        if(checktimestamp(recv_timestamp) == 1){
                            checkreturnint(send(selind, (void*)"timeout", CMDLEN, 0), "error sending fail");
                            continue;
                        }

                        puts("sending ok response to client");
                        checkreturnint(send(selind, (void*)"ok", CMDLEN, 0), "error sending ok");
                        
                        char* salt = malloc(SALT_LEN);
                        if (!RAND_bytes((unsigned char*) salt, SALT_LEN)) {
                            perror("RAND_bytes failed");
                            exit(EXIT_FAILURE);
                        }
                        unsigned char* salted_hashedpwd = malloc(HASH_SIZE);
                        compute_sha256_salted((unsigned char*)hashedpsw, strlen(hashedpsw),salted_hashedpwd, salt);
                        checkreturnint(addinfo(clients, selind, username, email, salted_hashedpwd, salt), "addinfo error");
                        printlist(clients);
                        free(reg_iv);
                        free(ciphertext);
                        free(salted_hashedpwd);
                        free(salt);
                        } 
                    else if (strcmp(cmd, "login") == 0) {
                        printf(YELLOW "Login request received\n" RESET);
                        ClientNode* current = findclient(clients, selind);
                        if(current->hs == 0){
                            printf(RED "Client #%d has not completed handshake\n" RESET, selind);
                            checkreturnint(send(selind, (void*)"nohs", CMDLEN, 0), "error sending nohs");
                            continue;
                        }
                        unsigned char shared_secret[SHARED_SECRET_LEN];
                        unsigned char AES_256_key[AES_KEY_LEN];
                        memcpy(shared_secret, current->sharedSecret, SHARED_SECRET_LEN);
                        memcpy(AES_256_key, current->sessionKey, AES_KEY_LEN);
                        int shared_secret_len = SHARED_SECRET_LEN;
                        unsigned char* login_iv = (unsigned char*)malloc(IV_SIZE);
                        receiveIVHMAC(selind, login_iv, shared_secret, shared_secret_len);
                        // receiving ciphertext
                        uint32_t ciphertext_len_n;
                        checkreturnint(recv(selind, (void*)&ciphertext_len_n, sizeof(uint32_t), 0), "error receiving ct len");
                        long ciphertext_len = ntohl(ciphertext_len_n);
                        unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
                        checkreturnint(recv(selind, (void*) ciphertext, ciphertext_len, 0), "error receiving ct");

                        // receive HMAC length
                        uint32_t hmac_len_n;
                        checkreturnint(recv(selind, (void*)&hmac_len_n, sizeof(uint32_t), 0), "error receiving HMAC length");
                        long hmac_len = ntohl(hmac_len_n);
                        unsigned char* recv_hmac = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
                        checkreturnint(recv(selind, (void*)recv_hmac, hmac_len, 0), "error receiving HMAC");

                        // compute HMAC of the ciphertext
                        unsigned char* computed_hmac;
                        unsigned int computed_hmac_len;
                        computed_hmac = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
                        compute_hmac(ciphertext, ciphertext_len, shared_secret, shared_secret_len, computed_hmac, &computed_hmac_len);
                        

                        if(CRYPTO_memcmp(computed_hmac, recv_hmac, computed_hmac_len) != 0){
                            checkreturnint(send(selind, (void*)"fail", CMDLEN, 0), "error sending fail");
                            printf("HMACs do not match, login failed.\n");
                            continue;
                        }
                        else{
                            printf("HMACs match, login validated\n");
                        }
                        free(computed_hmac);
                        free(recv_hmac);

                        char* plaintext = malloc(BUF_SIZE);
                        int plaintext_len;
                        decrypt_message(ciphertext, ciphertext_len, AES_256_key, login_iv, (unsigned char*)plaintext, &plaintext_len);
                        
                        char* username = strtok(plaintext, ",");
                        char* hashedpsw = strtok(NULL, ",");
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

                        if(checkpwd(current, hashedpsw) == 1){
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

                        continue;
                    } else if (strcmp(cmd, "list") == 0) {
                        printf(YELLOW "List request received\n" RESET);
                        if(isloggedin(clients, getusername(clients, selind)) == 0){
                            checkreturnint(send(selind, (void*)"notlogged", CMDLEN, 0), "error sending notlogged");
                            continue;
                        }
                        ClientNode* current = findclient(clients, selind);
                        unsigned char shared_secret[SHARED_SECRET_LEN];
                        unsigned char AES_256_key[AES_KEY_LEN];
                        memcpy(shared_secret, current->sharedSecret, SHARED_SECRET_LEN);
                        memcpy(AES_256_key, current->sessionKey, AES_KEY_LEN);
                        int shared_secret_len = SHARED_SECRET_LEN;

                        // receive IV
                        unsigned char* list_iv = (unsigned char*)malloc(IV_SIZE);
                        receiveIVHMAC(selind, list_iv, shared_secret, shared_secret_len);

                        // receive ciphertext length & ciphertext
                        uint32_t ciphertext_len_n;
                        checkreturnint(recv(selind, (void*)&ciphertext_len_n, sizeof(uint32_t), 0), "error receiving ct len");
                        long ciphertext_len = ntohl(ciphertext_len_n);
                        unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
                        checkreturnint(recv(selind, (void*)ciphertext, ciphertext_len, 0), "error receiving ct");

                        // receive HMAC length
                        uint32_t hmac_len_n;
                        checkreturnint(recv(selind, (void*)&hmac_len_n, sizeof(uint32_t), 0), "error receiving HMAC length");
                        long hmac_len = ntohl(hmac_len_n);
                        unsigned char* recv_hmac = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
                        checkreturnint(recv(selind, (void*)recv_hmac, hmac_len, 0), "error receiving HMAC");

                        // compute HMAC of the ciphertext
                        unsigned char* computed_hmac;
                        unsigned int computed_hmac_len;
                        computed_hmac = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
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
                        char* plaintext = malloc(12);
                        int plaintext_len;
                        decrypt_message(ciphertext, ciphertext_len, AES_256_key, list_iv, (unsigned char*)plaintext, &plaintext_len);
                        
                        int n = atoi(plaintext);

                        if(isloggedin(clients, getusername(clients, selind)) == 0){
                            checkreturnint(send(selind, (void*)"notlogged", CMDLEN, 0), "error sending notlogged");
                            continue;
                        }
                        
                        checkreturnint(send(selind, (void*)"ok", CMDLEN, 0), "error sending ok");

                        unsigned char* iv = (unsigned char*)malloc(IV_SIZE);
                        iv_comm(selind, iv, shared_secret, shared_secret_len);

                        char buffer[BUF_SIZE];
                        get_last_n_messages(messages, n, buffer, BUF_SIZE, srv_AES_256_key);
                        
                        unsigned char* enc_buffer = (unsigned char*)malloc(BUF_SIZE*n+16);
                        int enc_buffer_len;
                        // encrypting buffer with AES CBC to send it to client
                        encrypt_message(buffer, strlen(buffer)+1, AES_256_key, iv, enc_buffer, &enc_buffer_len);
                        // send the encrypted buffer length to the client
                        uint32_t enc_buffer_len_n = htonl(enc_buffer_len);
                        checkreturnint(send(selind, (void*)&enc_buffer_len_n, sizeof(uint32_t), 0), "error sending encrypted buffer length");
                        // send the encrypted buffer to the client
                        checkreturnint(send(selind, (void*)enc_buffer, enc_buffer_len, 0), "error sending encrypted buffer");
                        
                        // computing HMAC of the encrypted buffer
                        unsigned char* encbuffer_hmac = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
                        unsigned int encbuffer_hmac_len;
                        compute_hmac(enc_buffer, enc_buffer_len, shared_secret, shared_secret_len, encbuffer_hmac, &encbuffer_hmac_len);
                        // send the HMAC length to the client
                        uint32_t encbuffer_hmac_len_n = htonl(encbuffer_hmac_len);
                        checkreturnint(send(selind, (void*)&encbuffer_hmac_len_n, sizeof(uint32_t), 0), "error sending HMAC length");
                        // send the HMAC to the client
                        checkreturnint(send(selind, (void*)encbuffer_hmac, encbuffer_hmac_len, 0), "error sending HMAC");
                        free(ciphertext);
                        free(list_iv);
                        free(encbuffer_hmac);
                        free(enc_buffer);
                        free(iv);
                        free(computed_hmac);
                        free(recv_hmac);
                        free(plaintext);
                        continue;
                    } else if (strcmp(cmd, "get") == 0) {
                        printf(YELLOW "Get request received\n" RESET);
                        if(isloggedin(clients, getusername(clients, selind)) == 0){
                            checkreturnint(send(selind, (void*)"notlogged", CMDLEN, 0), "error sending notlogged");
                            continue;
                        }
                        
                        ClientNode* current = findclient(clients, selind);
                        unsigned char shared_secret[SHARED_SECRET_LEN];
                        unsigned char AES_256_key[AES_KEY_LEN];
                        memcpy(shared_secret, current->sharedSecret, SHARED_SECRET_LEN);
                        memcpy(AES_256_key, current->sessionKey, AES_KEY_LEN);
                        int shared_secret_len = SHARED_SECRET_LEN;

                        // receive IV
                        unsigned char* get_iv = (unsigned char*)malloc(IV_SIZE);
                        receiveIVHMAC(selind, get_iv, shared_secret, shared_secret_len);

                        // receive ciphertext length & ciphertext
                        uint32_t ciphertext_len_n;
                        checkreturnint(recv(selind, (void*)&ciphertext_len_n, sizeof(uint32_t), 0), "error receiving ct len");
                        long ciphertext_len = ntohl(ciphertext_len_n);
                        unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
                        checkreturnint(recv(selind, (void*)ciphertext, ciphertext_len, 0), "error receiving ct");

                        // receive HMAC length
                        uint32_t hmac_len_n;
                        checkreturnint(recv(selind, (void*)&hmac_len_n, sizeof(uint32_t), 0), "error receiving HMAC length");
                        long hmac_len = ntohl(hmac_len_n);
                        unsigned char* recv_hmac = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
                        checkreturnint(recv(selind, (void*)recv_hmac, hmac_len, 0), "error receiving HMAC");

                        // compute HMAC of the ciphertext
                        unsigned char* computed_hmac;
                        unsigned int computed_hmac_len;
                        computed_hmac = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
                        compute_hmac(ciphertext, ciphertext_len, shared_secret, shared_secret_len, computed_hmac, &computed_hmac_len);

                        if(CRYPTO_memcmp(computed_hmac, recv_hmac, computed_hmac_len) != 0){
                            checkreturnint(send(selind, (void*)"fail", CMDLEN, 0), "error sending fail");
                            printf("HMACs do not match, get failed.\n");
                            continue;
                        }
                        else{
                            printf("HMACs match, get validated\n");
                        }

                        free(computed_hmac);
                        free(recv_hmac);

                        // decrypt the ciphertext
                        char* plaintext = malloc(12);
                        int plaintext_len;
                        decrypt_message(ciphertext, ciphertext_len, AES_256_key, get_iv, (unsigned char*)plaintext, &plaintext_len);
                        free(ciphertext);
                        free(get_iv);

                        int mid = atoi(plaintext);
                        free(plaintext);

                        if(isloggedin(clients, getusername(clients, selind)) == 0){
                            checkreturnint(send(selind, (void*)"notlogged", CMDLEN, 0), "error sending notlogged");
                            continue;
                        }

                        checkreturnint(send(selind, (void*)"ok", CMDLEN, 0), "error sending ok");

                        unsigned char* iv = (unsigned char*)malloc(IV_SIZE);
                        iv_comm(selind, iv, shared_secret, shared_secret_len);

                        char buffer[BUF_SIZE];
                        getmessage(messages, mid, buffer, BUF_SIZE, srv_AES_256_key);

                        unsigned char* enc_buffer = (unsigned char*)malloc(BUF_SIZE+16);
                        int enc_buffer_len;
                        // encrypting buffer with AES CBC to send it to client
                        encrypt_message(buffer, strlen(buffer)+1, AES_256_key, iv, enc_buffer, &enc_buffer_len);
                        // send the encrypted buffer length to the client
                        uint32_t enc_buffer_len_n = htonl(enc_buffer_len);
                        checkreturnint(send(selind, (void*)&enc_buffer_len_n, sizeof(uint32_t), 0), "error sending encrypted buffer length");
                        // send the encrypted buffer to the client
                        checkreturnint(send(selind, (void*)enc_buffer, enc_buffer_len, 0), "error sending encrypted buffer");

                        // computing HMAC of the encrypted buffer
                        unsigned char* encbuffer_hmac = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
                        unsigned int encbuffer_hmac_len;
                        compute_hmac(enc_buffer, enc_buffer_len, shared_secret, shared_secret_len, encbuffer_hmac, &encbuffer_hmac_len);
                        // send the HMAC length to the client
                        uint32_t encbuffer_hmac_len_n = htonl(encbuffer_hmac_len);
                        checkreturnint(send(selind, (void*)&encbuffer_hmac_len_n, sizeof(uint32_t), 0), "error sending HMAC length");
                        // send the HMAC to the client
                        checkreturnint(send(selind, (void*)encbuffer_hmac, encbuffer_hmac_len, 0), "error sending HMAC");
                        free(encbuffer_hmac);
                        free(enc_buffer);
                        free(iv);
                        continue;
                    } else if (strcmp(cmd, "add") == 0) {
                        printf(YELLOW "Add request received\n" RESET);
                        ClientNode* current = findclient(clients, selind);
                        if(current->hs == 0){
                            printf(RED "Client #%d has not completed handshake\n" RESET, selind);
                            checkreturnint(send(selind, (void*)"nohs", CMDLEN, 0), "error sending nohs");
                            continue;
                        }
                        unsigned char shared_secret[SHARED_SECRET_LEN];
                        unsigned char AES_256_key[AES_KEY_LEN];
                        memcpy(shared_secret, current->sharedSecret, SHARED_SECRET_LEN);
                        memcpy(AES_256_key, current->sessionKey, AES_KEY_LEN);
                        int shared_secret_len = SHARED_SECRET_LEN;
                        
                        unsigned char* add_iv = (unsigned char*)malloc(IV_SIZE);
                        receiveIVHMAC(selind, add_iv, shared_secret, shared_secret_len);

                        // receiving ciphertext
                        uint32_t ciphertext_len_n;
                        checkreturnint(recv(selind, (void*)&ciphertext_len_n, sizeof(uint32_t), 0), "error receiving ct len");
                        long ciphertext_len = ntohl(ciphertext_len_n);
                        unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
                        checkreturnint(recv(selind, (void*) ciphertext, ciphertext_len, 0), "error receiving ct");

                        // receive HMAC length
                        uint32_t hmac_len_n;
                        checkreturnint(recv(selind, (void*)&hmac_len_n, sizeof(uint32_t), 0), "error receiving HMAC length");
                        long hmac_len = ntohl(hmac_len_n);
                        unsigned char* recv_hmac = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
                        checkreturnint(recv(selind, (void*)recv_hmac, hmac_len, 0), "error receiving HMAC");

                        // compute HMAC of the ciphertext
                        unsigned char* computed_hmac;
                        unsigned int computed_hmac_len;
                        computed_hmac = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
                        compute_hmac(ciphertext, ciphertext_len, shared_secret, shared_secret_len, computed_hmac, &computed_hmac_len);
                        

                        if(CRYPTO_memcmp(computed_hmac, recv_hmac, computed_hmac_len) != 0){
                            checkreturnint(send(selind, (void*)"fail", CMDLEN, 0), "error sending fail");
                            printf("HMACs do not match, add failed.\n");
                            continue;
                        }
                        else{
                            printf("HMACs match, add validated\n");
                        }
                        free(computed_hmac);
                        free(recv_hmac);

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

                        char* title = strtok(plaintext, ",");
                        char* body = strtok(NULL, "\0");

                        unsigned char enc_body [BODY_LEN];
                        int enc_body_len;
                        encrypt_message_AES256ECB((unsigned char*)body, strlen(body)+1, srv_AES_256_key, enc_body, &enc_body_len);

                        Message* message = create_message(messagecount, enc_body_len, current->username, title, enc_body);
                        
                        insert_message(&messages, message);
                        messagecount++;
                        puts("list after add:");
                        print_messagelist(messages);

                        continue;
                    } else if (strcmp (cmd, "logout") == 0) {
                        printf(YELLOW "Logout request received\n" RESET);
                        ClientNode* current = findclient(clients, selind);
                        if(current -> hs == 0){
                            printf(RED "Client #%d has not completed handshake\n" RESET, selind);
                            checkreturnint(send(selind, (void*)"nohs", CMDLEN, 0), "error sending nohs");
                            continue;
                        }

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
                        //printf("public key received from client\n");
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

                        //printf("public key length sent to server\n");
                        fflush(stdout);
        
                        // Send the serialized public key to the server
                        checkreturnint(send(selind, (void*)srv_pkey_buf, srv_pub_key_len, 0), "Error sending public key");

                        //printf("public key sent to client\n");
                        fflush(stdout);
                        
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
                        free(signature);

                        // Generate the shared secret
                        EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(server_keypair, NULL);
                        EVP_PKEY_derive_init(ctx_drv);
                        EVP_PKEY_derive_set_peer(ctx_drv, client_public_key);
                        unsigned char* shared_secret;

                        size_t shared_secret_len;
                        EVP_PKEY_derive(ctx_drv, NULL, &shared_secret_len);
                        //printf("Shared secret length: %ld\n", shared_secret_len);

                        shared_secret = (unsigned char*)malloc(shared_secret_len);
                        EVP_PKEY_derive(ctx_drv, shared_secret, &shared_secret_len);

                        current->hs = 1;
                        memcpy(current->sharedSecret, shared_secret, SHARED_SECRET_LEN);
                        unsigned char* AES_256_key;
                        EVP_MD_CTX* keyctx;
                        AES_256_key = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
                        compute_sha256(shared_secret, shared_secret_len, AES_256_key);
                        memcpy(current->sessionKey, AES_256_key, AES_KEY_LEN);
                        free(AES_256_key);
                        current->status = 0;
                    } else {
                        printf(RED "Invalid cmd received.\n" RESET);
                        continue;
                    }
                }
                /*
                FD_CLR(selind, &master);
                close(selind);
                fflush(stdout);
                */
            }
        }
    }
    EVP_PKEY_free(server_pub_key);
    X509_free(server_cert);
    free(cert_buf);
    free_clientlist(clients);
    free_messagelist(messages);
}
    
    
    
