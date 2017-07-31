#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#define BUFFER_SIZE 4096

unsigned char* makePacket(char* interface, char* gateway_ip);
void printPacket(unsigned char* packet,int len);
int checkForm(char* form, char* string);
void inputMacAddr(unsigned char* packet, char* addr);
void mac_eth0(unsigned char MAC_str[13], char* interface);


int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    char s_ip[16],t_ip[16];

    if (argc !=4){
        puts("usage : send_arp wlan0 [sender ip] [targetip]");
        return 0;
    }
    dev=argv[1];
    strcpy(s_ip,argv[2]);
    strcpy(t_ip,argv[3]);
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }


    //  Making packet  //
    unsigned char* packet = (unsigned char *)malloc(42*sizeof(unsigned char));
    packet = makePacket(dev,t_ip);
    printPacket(packet,42);

    //  Sending packet  //
    if (pcap_sendpacket(handle, packet, 42 /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
        return -1;
    }

    // Recieving packet  //
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *rpacket;		/* The actual packet */

    int retValue;
    /* Grab a packet */
    retValue = pcap_next_ex(handle, &header, &rpacket);
    if( retValue <= 0 ){
        printf("Error grabbing packet");
        return -1;
    }
    /* Print its length */
    printf("##########     Total packet length : [%d (0x%x)]     ##########\n", header->len, header->len);
    printPacket((unsigned char*)rpacket, header->len);

//    struct ether_header* rpacket_ether;

    pcap_close(handle);
    return 0;
}

//////////functions

int checkForm(char* form, char* string)
{
    int len=strlen(form), i;
    if ( (unsigned)len != strlen(string) )
        return -1;
    for (i=0;i<len;i++)
    {
        if (form[i] == 'H'){
            if(!((string[i]>='a' && string[i] <='f') || (string[i] >='A' && string[i]<='F') || (string[i]>='0' && string[i] <='9') ))
                return -1;
        }
        else{
            if(form[i] != string[i])
                return -1;
        }
    }
    return 0;
}

void mac_eth0(unsigned char MAC_str[13], char* interface)
{
    int s,i;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    for (i=0; i<ETH_ALEN; i++)
        sprintf((char *)&MAC_str[i*2],"%02X",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
    MAC_str[12]='\0';
}

unsigned char* makePacket(char* interface, char* gateway_ip)
{
    int i,fd;
    unsigned char* packet = (unsigned char *)malloc(42*sizeof(unsigned char));
    struct ifreq ifr;
    char mymac[20];
    struct ether_header *etherHead;
    struct arphdr *arpHead;

    etherHead = (struct ether_header*) packet;
    inputMacAddr(packet,"FFFFFF-FFFFFF");

    mac_eth0((unsigned char*)mymac,interface);
    for (i=13;i>6;i--)
        mymac[i]=mymac[i-1];
    mymac[6]='-';
    inputMacAddr(packet+6,mymac);
    etherHead->ether_type=htons(ETH_P_ARP);

    //ETHERNET End  //ARP Start
    arpHead= (struct arphdr*)(packet+ETH_HLEN);
    arpHead->ar_hrd = htons(ARPHRD_ETHER);
    arpHead->ar_pro = htons(ETHERTYPE_IP);
    arpHead->ar_hln = 0x06;
    arpHead->ar_pln = 0x04;
    arpHead->ar_op = htons(ARPOP_REQUEST);

    //Input mymac address

    inputMacAddr(packet+ETH_HLEN+8,mymac);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    long ipaddr = inet_addr(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    memcpy(packet+ETH_HLEN+14,&ipaddr,4);

    //Destination part
    inputMacAddr(packet+ETH_HLEN+18,"000000-000000");
    ipaddr=inet_addr(gateway_ip);
    memcpy(packet+ETH_HLEN+24,&ipaddr,4);

    return packet;
}

void inputMacAddr(unsigned char* packet, char* addr)
{
    char *endptr;
    char temp[10]={0,};
    for (int j=0; j<3; j++){
        memcpy(temp,addr+j*2,2);
        temp[2]=0;
        packet[j] = (unsigned char)strtol(temp, &endptr, 16);
    }
    for (int j=0; j<3; j++){
        memcpy(temp,addr+7+j*2,2);
        temp[2]=0;
        packet[3+j] = (unsigned char)strtol(temp, &endptr, 16);
    }
}

void printPacket(unsigned char* packet,int len)
{
    int i;
    for ( i=0; i < len ; i++ ){
        if (i%16 ==0 && i != 0){
            printf("  ");
            for ( int j=-16;j<=-1;j++ ){
                if (j == -8)
                    printf("  ");
                if (isprint(*(packet+i+j)))
                    printf("%c", *(packet+i+j));
                else
                    printf(".");
            }
            printf("\n");
        }
        if ( i % 8 ==0 )
            printf ("  ");
        printf("%02x ", *(packet+i));
    }
    for(i=0;i<16-(len%16);i++){
        printf("   ");
        if ( i % 8 ==0 )
            printf ("  ");
    }
    for ( int i=(len/16)*16;i<len;i++ ){
        if (i%8 == 0 && i%16 != 0)
            printf("  ");
        if (isprint(*(packet+i)))
            printf("%c", *(packet+i));
        else
            printf(".");
    }
    printf("\n");
}
