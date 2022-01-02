#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include<netinet/tcp.h>

struct ethheader
{

    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;

};

struct ipheader
{

    unsigned char iph_ih1:4,iph_ver:4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3,iph_offset:13;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;




};






void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet ;

    if (ntohs (eth->ether_type ) == 0x0800)
    { // Ox0800 is IP type
        struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)) ;
       // printf("From : %s\n",inet_ntoa(ip->iph_sourceip));
       // printf("To : %s\n",inet_ntoa(ip->iph_destip));

       
        
      

      //  printf("%s\n",tcp);

        switch(ip->iph_protocol)
        {

            case IPPROTO_TCP :
                printf("TCP received\n");
                
                printf("From : %s\n",inet_ntoa(ip->iph_sourceip));
        printf("To : %s\n",inet_ntoa(ip->iph_destip));
                int ip_header_len = ip->iph_ih1*4;

        struct tcphdr  *tcp_segment=(struct tcphdr *)(packet+sizeof(struct ethheader ) + ip_header_len) ;
        
        int tcp_header_len=tcp_segment->doff*4;
        
        u_char *s=(u_char *)(packet+sizeof(struct ethheader ) + ip_header_len+tcp_header_len);
        
        
        printf("%s\n",s);
        
        
        
        
                return;

            case IPPROTO_UDP :
               // printf("UDP received\n");
                return;

            case IPPROTO_ICMP :
               // printf("ICMP received\n");
                return;


            default:
               // printf("others received\n");
                return;


        }
    }



}





int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    char filter_exp[]="ip proto tcp";

    bpf_u_int32 net ;

    handle= pcap_open_live ("enp0s3", BUFSIZ , 1, 1000, errbuf );

    pcap_compile (handle , &fp, filter_exp , 0 , net) ;
    pcap_setfilter(handle, &fp );

    pcap_loop(handle , -1, got_packet , NULL);


    pcap_close (handle );
    return 0;




}
