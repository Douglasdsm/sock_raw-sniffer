#include <error.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include<signal.h>
#include<netinet/ip_icmp.h>	//Fornece declarações para o cabeçalho icmp
#include<netinet/udp.h>	//Fornece declarações para o cabeçalho udp
#include<netinet/tcp.h>	//Fornece declarações para o cabeçalho tcp
#include<netinet/ip.h>	//Fornece declarações para o cabeçalho IP
#include<netinet/if_ether.h>	//Para ETH_P_ALL
#include<net/ethernet.h>	//Para ether_header
#include <arpa/inet.h>
#include <time.h> //clock(), CLOCKS_PER_SEC e clock_t
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>

#define MAX_LENGTH 32768
double dadosEnviados = 0;
double dadosRecebidos = 0;

double t; //variável para armazenar tempo de inicio
double tf; //variável para armazenar tempo do fim
double tr; //variável para armazenar tempo resultante
struct pcap_header {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t linktype;
}__attribute__((packed));

struct pcap_packethdr {
	struct timeval ts;
	uint32_t caplen;
	uint32_t len;
};

struct eth_hdr {
	uint8_t ether_dhost[6];
	uint8_t ether_shost[6];
	uint16_t ether_type;
}__attribute__((packed));

struct ip_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t ihl:4;
	uint8_t version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t version:4;
	uint8_t ihl:4;
#endif

	uint8_t tos;
	uint16_t total_len;
	uint16_t id;
	uint16_t fragmentation_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t ip_src;
	uint32_t ip_dst;
}__attribute__((packed));

struct tcp_hdr {
uint16_t tcp_src;
uint16_t tcp_dst;
uint32_t tcp_seq_num;
uint32_t tcp_ack_num;
uint8_t tcp_res1:4;
uint8_t tcp_hdr_len:4;
uint8_t tcp_fin:1;
uint8_t tcp_syn:1;
uint8_t tcp_rst:1;
uint8_t tcp_psh:1;
uint8_t tcp_ack:1;
uint8_t tcp_urg:1;
uint8_t tcp_res2:2;
uint16_t tcp_win_size;
uint16_t tcp_chk;
uint16_t tcp_urg_ptr;


}__attribute__((packed));

struct udp_hdr {
	uint16_t port_src;
	uint16_t port_dst;
	uint16_t length;
	uint16_t checksum;
}__attribute__((packed));

int recebendo = 1;
double tempo()
{
 struct timeval tv;
 gettimeofday(&tv,0);

 return tv.tv_sec + tv.tv_usec/1e6;
}

void  meutratadordesinal(int sig){
       
       tf = tempo();
       tr = (tf - t);
       
       recebendo = 0;
       printf("\ntaxa de transmissao  de download: ");
       if((dadosRecebidos / tr)>  1000000000){
       		printf("%.0fGB/s",((dadosRecebidos/tr)*1000));
       		printf("\n download = %.0fGB",(dadosRecebidos/1000000000));
       }else if((dadosRecebidos / tr)>1000000){
       		printf("%.0fMB/s",((dadosRecebidos/tr)*1000));
       		printf("\n download= %.0fMB",(dadosRecebidos/1000000));
       }else{
       		printf("%.0fkB/s",((dadosRecebidos/tr)*1000));
       		printf("\n download = %.0fkB",dadosRecebidos);
       }
       printf("\ntaxa de transmissao de upload: ");
       if((dadosEnviados/ tr) >  1000000000){
       		printf("%.0fGB/s",((dadosEnviados/tr)*1000));
       		printf("\nupload = %.0fGB",(dadosEnviados/1000000000));
       }else if((dadosEnviados/ tr) >1000000){
       		printf("%.0fMB/s",((dadosEnviados/tr)*1000));
       		printf("\nupload = %.0fMB",(dadosEnviados/1000000));
       }else{
       		printf("%.0fkB/s",((dadosEnviados/tr)*1000));
       		printf("\nupload = %.0fkB\n",dadosEnviados);
       }
       
      

}
char endIP[17];
void ip(char interface[]){
struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) 
    {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }


    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
    {
        if (ifa->ifa_addr == NULL)
            continue;  

        s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

        if((strcmp(ifa->ifa_name,interface)==0)&&(ifa->ifa_addr->sa_family==AF_INET))
        {
            if (s != 0)
            {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            
            
            strcpy(endIP,host);
            
        }
    }

    freeifaddrs(ifaddr);
    



}



int main(int argc, char **argv){
//printf("Argv[0] = %s\nArgv[1] = %s\nArgv[2]= %s\nArgv[3] = %s\nArgv[4]=%s\n",argv[0],argv[1],argv[2],argv[3],argv[4]);
	t = tempo();
	if(argc == 5){
		int argumentos =  strcmp("-w",argv[1])+strcmp("-i",argv[3]);
		
		if(argumentos == 0){
			FILE *fp = fopen(argv[2],"wb");
			if(!fp){
				printf("\nErro ao criar arquivo\n");
				return 0;
			}
			struct pcap_header pheader;
			pheader.magic = 0xA1B2C3D4;
			pheader.version_major = 0X0002;
			pheader.version_minor = 0X0004;
			pheader.thiszone = 0;
			pheader.sigfigs = 0;
			pheader.snaplen = 0X00040000;
			pheader.linktype = 0X00000001;
			//printf("\nArquivo criado com sucesso\n");
			fwrite(&pheader, sizeof(struct pcap_header),1,fp);


			int n;
    			int sockfd;
			int sockopt;
			struct ifreq ifopts;
			unsigned char buffer[2048];

			if(argc != 5) {
				fprintf(stderr, "Usage: %s <iface>\n", argv[0]);
				exit(-1);
			}
			sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
			
			if(sockfd < -1) {
				fprintf(stderr, "ERROR1: %s\n", strerror(errno));
				exit(-1);
			}

			strncpy(ifopts.ifr_name, argv[4], IFNAMSIZ - 1);
			ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
			ifopts.ifr_flags |= IFF_PROMISC;
			ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

			if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) == -1) {
				fprintf(stderr, "ERROR: primeiro %s\n", strerror(errno));
				close(sockfd);
				exit(-1);
			}
			
			//printf("\nInterface: %s\n",argv[4]);
			if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, argv[4], IFNAMSIZ-1) == -1){
				fprintf(stderr, "ERROR: segundo  %s\n", strerror(errno));
				close(sockfd);
				exit(-1);
			}
			
			
			
			struct pcap_packethdr hpcap;
			 ip(argv[4]);
			signal(SIGINT,meutratadordesinal);
			
			while(recebendo){
			
				 
				memset(buffer, 0, sizeof(buffer));
			

				n = recv(sockfd, buffer, sizeof(buffer), 0);
			

				if(n < 0) {
					fprintf(stderr, "ERROR2: %s\n", strerror(errno));
					exit(-1);
				}
				
				
				struct eth_hdr *eth = (struct eth_hdr*) buffer;
				if(eth->ether_type != 0x0008) {

					//NOT IP
					continue;
				}
				

				if(n > 3) {
					
					

					gettimeofday(&hpcap.ts,NULL);

					struct ip_hdr *ip = (struct ip_hdr*)(buffer + sizeof(struct eth_hdr));
					char src[INET_ADDRSTRLEN];
					char dst[INET_ADDRSTRLEN];
					inet_ntop(AF_INET,&(ip->ip_src),src,INET_ADDRSTRLEN);
					inet_ntop(AF_INET,&(ip->ip_dst),dst,INET_ADDRSTRLEN);
					if(!strcmp(endIP,src)){
						
						dadosEnviados = dadosEnviados + ntohs(ip->total_len);
						
						
					}else{
						
						
						dadosRecebidos = dadosRecebidos + ntohs(ip->total_len);
						
						
					}
					
		
					
					
					
					if(ip->protocol==6){
						unsigned short ip_hdrlen;
						struct ip_hdr *ip_h = (struct ip_hdr *)( buffer  + sizeof(struct eth_hdr) );
						ip_hdrlen = ip_h->ihl*4;

						hpcap.caplen = sizeof(struct eth_hdr)+ip_hdrlen +sizeof(struct tcp_hdr);
						hpcap.len = sizeof(struct eth_hdr)+ip_hdrlen +sizeof(struct tcp_hdr);
						fwrite(&hpcap, sizeof(struct pcap_packethdr),1,fp);


						struct eth_hdr *eth = (struct eth_hdr *)buffer;
						fwrite(eth, sizeof(struct eth_hdr),1,fp);

						struct ip_hdr *ip = (struct ip_hdr *)(buffer  + sizeof(struct eth_hdr));
						fwrite(ip, ip_hdrlen,1,fp);

						struct tcp_hdr *tcp = (struct tcp_hdr*)(buffer + ip_hdrlen + sizeof(struct eth_hdr));
						fwrite(tcp, sizeof(struct tcp_hdr),1,fp);

						
					
					}else if(ip->protocol==17){
						
						unsigned short ip_hdrlen;
						struct ip_hdr *ip_h = (struct ip_hdr *)( buffer  + sizeof(struct eth_hdr) );
 				           	ip_hdrlen = ip_h->ihl*4;
						
						hpcap.caplen = sizeof(struct eth_hdr)+ip_hdrlen +sizeof(struct udp_hdr);
						hpcap.len = sizeof(struct eth_hdr)+ip_hdrlen +sizeof(struct udp_hdr);
						fwrite(&hpcap, sizeof(struct pcap_packethdr),1,fp);

						struct eth_hdr *eth = (struct eth_hdr *)buffer;
						fwrite(eth, sizeof(struct eth_hdr),1,fp);
						
						struct ip_hdr *ip = (struct ip_hdr *)(buffer  + sizeof(struct eth_hdr) );
                        			fwrite(ip,ip_hdrlen,1,fp);
						
						struct udp_hdr *udp = (struct udp_hdr*)(buffer +  ip_hdrlen + sizeof(struct eth_hdr));
						fwrite(udp, sizeof(struct udp_hdr),1,fp);
						
						
					}
				}	
			tf = tempo(); 
			}//fechamento while recv
				
			fclose(fp);
    			close(sockfd);
		}else{
			printf("Argumentos invalidos tente\n ./executavel -w nomedoarquivo.pcap -i interface\nOU\n./executavel -r nomedoarquivo.pcap");
		}

	}else if(argc == 3){
		int argumento = strcmp("-r",argv[1]);
		if(argumento == 0){
			FILE *fp = fopen(argv[2], "rb");
			if(!fp) {
				fprintf(stderr, "Error: %s\n", strerror(errno));
				return -1;
			}
			
			struct pcap_header pheader;
			fread(&pheader, sizeof(struct pcap_header), 1, fp);
			uint8_t buffer[MAX_LENGTH];
			struct pcap_packethdr pkthdr;
			int ret;
			while(1){
				ret = fread(&pkthdr, sizeof(struct pcap_packethdr), 1, fp);
				if(ret < 1){
					break;
				}
				memset(buffer, 0, MAX_LENGTH);
				fread(buffer, pkthdr.caplen, 1, fp);
				struct eth_hdr *eth = (struct eth_hdr*) buffer;
				if(eth->ether_type != 0x0008){
					continue;
				}
				printf("[Ethernet] %02x:%02x:%02x:%02x:%02x:%02x > %02x:%02x:%02x:%02x:%02x:%02x (Ipv4) [0x%x]\n",
				eth->ether_shost[0],
				eth->ether_shost[1],
				eth->ether_shost[2],
				eth->ether_shost[3],
				eth->ether_shost[4],
				eth->ether_shost[5],
				eth->ether_dhost[0],
		                eth->ether_dhost[1],
                		eth->ether_dhost[2],
	        	        eth->ether_dhost[3],
        	        	eth->ether_dhost[4],
            		        eth->ether_dhost[5],
				ntohs(eth->ether_type));

				struct ip_hdr *ip = (struct ip_hdr*) (buffer + sizeof(struct eth_hdr));
				char src[INET_ADDRSTRLEN];
				char dst[INET_ADDRSTRLEN];
				inet_ntop(AF_INET,&(ip->ip_src),src,INET_ADDRSTRLEN);
				inet_ntop(AF_INET,&(ip->ip_dst),dst,INET_ADDRSTRLEN);
				printf("[IPv4] Tam. Cab.: %d, Tamanho Total: %u, Identificação: ox%x,\nDeslocamento de Fragmento: %d, Tempo de Vida: %d,\nProtocolo:TCP[0x%d], Cheksum do cabeçalho: 0x%x.\n[IPv4] %s > %s.\n",
	                       ((unsigned int)(ip->ihl))*4,
        	                ntohs(ip->total_len),
                	        ntohs(ip->id),
                        	(unsigned int)ip->fragmentation_offset,
                        	(unsigned int)ip->ttl,
   	                        (unsigned int)ip->protocol,
                                ntohs(ip->checksum),
                                src,
                                dst);
				
				if(ip->protocol == 6) {
					struct tcp_hdr *tcp = (struct tcp_hdr*) (buffer + sizeof(struct eth_hdr) + ip->ihl*4);
					printf("[TCP] Port: %u > %u, Seq. Num.: 0x%u, Ack. Num.: 0x%u,\n Tam. Cab.: %d bytes, FLAGS: ",
					ntohs(tcp->tcp_src),
					ntohs(tcp->tcp_dst),
					ntohl(tcp->tcp_seq_num),
					ntohl(tcp->tcp_ack_num),
					(unsigned int)(tcp->tcp_hdr_len)*4);
					if((unsigned int)tcp->tcp_fin ){
					printf("FIN");
					}

					if((unsigned int)tcp->tcp_syn == 1 ){

					if((unsigned int)tcp->tcp_fin == 0){
					printf("SYN");
					}else{
					printf(" + SYN");
					}}

					if((unsigned int)tcp->tcp_rst == 1){
					if((unsigned int)tcp->tcp_fin == 0 && tcp->tcp_syn == 0){
					printf("RST");
					}else{
					printf(" + RST");
					}}


					if((unsigned int)tcp->tcp_psh == 1){
					if((unsigned int)tcp->tcp_rst == 0 && tcp->tcp_fin == 0 && tcp->tcp_syn == 0 ){
					printf("PSH");
					}else{
					printf(" + PSH");
					}}

					if((unsigned int)tcp->tcp_ack == 1){
					if((unsigned int)tcp->tcp_psh == 0 && tcp->tcp_rst == 0 && tcp->tcp_fin == 0 && tcp->tcp_syn == 0){
					printf("ACK");
					}else{
					printf(" + ACK");
					}}

					if((unsigned int)tcp->tcp_urg == 1 ){
					if((unsigned int)tcp->tcp_ack == 0 && tcp->tcp_psh == 0 && tcp->tcp_rst == 0 && tcp->tcp_fin == 0 && tcp->tcp_syn == 0){
					printf("URG");
					}else{
					printf(" + URG");
					}}

					printf(",\nTam. Jan.: %d, Checksum: 0x%x.\n",
					ntohs(tcp->tcp_win_size),
					ntohs(tcp->tcp_chk));


				}else if(ip->protocol == 17){
					struct udp_hdr *udp = (struct udp_hdr*) (buffer + sizeof(struct eth_hdr) + ip->ihl*4);
					printf("[UDP] Port: %u > %u, Tamanho: %u, Checksum: 0x%x\n",
                                        ntohs(udp->port_src),
                                        ntohs(udp->port_dst),
                                        ntohs(udp->length),
                                        ntohs(udp->checksum));

				
				}

			}//fim do while
		fclose(fp);

		}//if do argumento teste se eh igual a -r



	}else{
	printf("\nComando nao reconhecido ");
	}



return 0;
}


