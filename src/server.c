#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define BUF_SIZE 4096

int main(int argc, char** argv){
    int lissoc, connectsoc;
    struct sockaddr_in srv_addr, client_addr;
    uint16_t port = (uint16_t)strtol(argv[1], NULL, 10);
    uint8_t dim;

    fd_set master;
    fd_set copy; //fd set utilizzato dalla select così non modifico il master

    FD_ZERO(&master);
    FD_ZERO(&copy);
    lissoc= socket(AF_INET, SOCK_STREAM, 0);
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family=AF_INET;
    srv_addr.sin_port=htons(port);
    inet_pton(AF_INET, "127.0.0.1", &srv_addr.sin_addr);

    if(bind(lissoc, (struct sockaddr*)& srv_addr, sizeof(srv_addr)) < 0){
        perror("bind error \n");
        exit(-1);
    }

    if(listen(lissoc, 10) < 0){
        perror("listen error \n");
        exit(-1);
    }
    FD_SET(0, &master); //Inserisco socket stdin tra i socket monitorati dalla select
    FD_SET(lissoc,&master);

    int fdmax;
    fdmax=lissoc;
    
    printf("Server inizializzato correttamente, attendo prima richiesta \n");
    fflush(stdout);

    int selind;

    while(1){
        copy=master;
        select(fdmax+1, &copy, NULL, NULL, NULL); //In copy vengono lasciati solo i socket pronti. I socket pronti in ascolto diventano pronti quando c'è una nuova connessione mentre quelli di connessione diventano pronti quando c'è un nuovo dato
        for(selind =0; selind <=fdmax; selind++){
            if(FD_ISSET(selind, &copy)){
                if(selind == 0){ //Socket pronto = stdin
                    // commands
                }
                else if(selind==lissoc){ //Pronto il codice di ascolto: nuovo dispositivo connesso
                    int len = sizeof (client_addr);
                    int ret;    
                    connectsoc = accept(lissoc, (struct sockaddr*) &client_addr, &len);
                    FD_SET(connectsoc, &master); //Inserisco nuovo socket in fd_set master
                    uint16_t codercv;
                    ret = recv(connectsoc, (void*)&codercv, sizeof(uint16_t),0); //Ricevo il tipo di connessione 
                    if(ret < 0 ){
                        perror("recv error");
                    }
                    int code = ntohs(codercv);
                    printf ("connesso con codice: %d", code);
                    fflush(stdout);
                    FILE* activeconn = fopen("activeconn.txt", "a");
                    fprintf(activeconn, "SOC%d UNAME%s\n", connectsoc, "UNDEF");
                    fclose(activeconn);
                    printf("Connessione effettuata da un client sul SOC %d\n", connectsoc);
                    fflush(stdout);
                    //ntohl
                    uint8_t dim;
                    ret = recv(connectsoc, (void*)&dim, sizeof(uint8_t),0); //receive the dimension of the username
                    if(ret < 0){
                        perror("recv error");
                        exit(-1);
                    }
                    printf("Dim: %d\n", dim);
                    fflush(stdout);
                    char username[dim+1];
                    ret = recv(connectsoc, (void*)username, dim, 0); //receive the username
                    if(ret < 0){
                        perror("recv error");
                        exit(-1);
                    }
                    username[dim] = '\0';
                    printf("Username: %s\n", username);
                    fflush(stdout);
                    activeconn = fopen ("activeconn.txt", "r");
                    if (activeconn == 0){
                        printf("Errore nell'apertura del file delle connessioni attive\n");
                        fflush(stdout);
                    }
                    FILE* activeconntmp = fopen ("activeconntmp.txt", "w");
                    if (activeconntmp == 0){
                        printf("Errore nella creazione del file delle connessioni temporaneo\n");
                        fflush(stdout);
                    }
                    int tmpsoc;
                    char tmpuname[BUF_SIZE];
                    while(fscanf(activeconn,"SOC%d UNAME%s\n",&tmpsoc,&tmpuname)!=EOF){
                        if(tmpsoc==connectsoc){
                            fprintf(activeconntmp, "SOC%d UNAME%s\n",tmpsoc,username);
                        }
                        else{
                            fprintf(activeconntmp, "SOC%d UNAME%s\n",tmpsoc,tmpuname);
                        }
                    }
                    fclose(activeconn);
                    fclose(activeconntmp);
                    if(connectsoc>fdmax) fdmax = connectsoc;
                }
                else{ //Operazione sul socket di connessione
                    //Qua faccio uno switch per verificare quale tipologia di dispositivo è. In questo modo posso differenziare le operazioni. Per fare ciò recupero le informazioni dal file
                    //Delle connessioni attive.
                }
            }
        }  
    }
}