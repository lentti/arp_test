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
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_arp.h>
#include <net/ethernet.h>
#include <netinet/in.h>


int makePacket();
void printPacket(unsigned char* packet,int len);
int checkForm(char* form, char* string);
void inputMacAddr(unsigned char* packet, char* addr);
void mac_eth0(unsigned char MAC_str[13], char* interface);

int main(int argc, char *argv[])
{
    makePacket();
    return 0;
}

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
    #define HWADDR_len 6
    int s,i;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    for (i=0; i<HWADDR_len; i++)
        sprintf((char *)&MAC_str[i*2],"%02X",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
    MAC_str[12]='\0';
}

int makePacket()
{
    int type,i;
    puts("Select packet type     ==========");
    puts("1. Normal ARP request");
    scanf("%d",&type);
    if ( type == 1 ){
        unsigned char* packet = (unsigned char *)malloc(42*sizeof(unsigned char));
        struct ether_header *etherHead;
        etherHead = (struct ether_header*) packet;
        char input[30];
        puts("Type Destination MAC Address (Form 012345-ABCDEF) (Type B to broadcast)");
        scanf("%s",input);
        if(!strcmp(input,"b"))
            inputMacAddr(packet,"FFFFFF-FFFFFF");
        else if(checkForm("HHHHHH-HHHHHH",input)){
            puts("Wrong Input");
            return -1;
        }
        else
            inputMacAddr(packet,input);
        puts("Type Source MAC Address (Form 012345-ABCDEF) (Type A to auto-check)");
        scanf("%s",input);
        if(!strcmp(input,"a")){
            mac_eth0((unsigned char*)input,"ens33");
            for (i=13;i>6;i--)
                input[i]=input[i-1];
            input[6]='-';
            inputMacAddr(packet+6,input);
        }
        etherHead->ether_type=htons(ETH_P_ARP);

        //ETHERNET End  //ARP Start
        puts("=======  ARP   ========");
        struct arphdr *arpHead;
        arpHead= (struct arphdr*)(packet+ETH_HLEN);
        arpHead->ar_hrd = htons(ARPHRD_ETHER);
        arpHead->ar_pro = htons(ETHERTYPE_IP);
        arpHead->ar_hln = 0x06;
        arpHead->ar_pln = 0x04;
        arpHead->ar_op = htons(ARPOP_REQUEST);


        puts("Type Sender MAC Address (Form 012345-ABCDEF) (Type A to auto-check)");
        scanf("%s",input);
        if(!strcmp(input,"a")){
            mac_eth0((unsigned char*)input,"ens33");
            for (i=13;i>6;i--)
                input[i]=input[i-1];
            input[6]='-';
            inputMacAddr(packet+ETH_HLEN+8,input);
        }

        int fd;
        struct ifreq ifr;

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, "ens33", IFNAMSIZ-1);
        ioctl(fd, SIOCGIFADDR, &ifr);
        close(fd);

        /* display result */
        printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
        printf("%x\n",htonl( inet_addr( inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr))));
        long ipaddr = inet_addr( inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
        memcpy(packet+ETH_HLEN+14,&ipaddr,4);

        printPacket(packet,42);
    }
    return 0;
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
