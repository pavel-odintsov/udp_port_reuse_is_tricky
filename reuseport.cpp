#include <iostream>
#include <thread>
#include <vector>
#include <array>

#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <linux/filter.h>

std::array<uint64_t, 512> packets_per_thread;

void start_netflow_collector(std::size_t thread_id, const std::string& netflow_host, unsigned int netflow_port, uint32_t netflow_threads_per_port) {
    std::cout << "Netflow plugin will listen on " << netflow_host << ":" << netflow_port << " udp port" << std::endl;

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    
    // AI_PASSIVE to handle empty netflow_host as bind on all interfaces
    // AI_NUMERICHOST to allow only numerical host
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

    addrinfo* servinfo = NULL;

    std::string port_as_string = std::to_string(netflow_port);

    int getaddrinfo_result = getaddrinfo(netflow_host.c_str(), port_as_string.c_str(), &hints, &servinfo);

    if (getaddrinfo_result != 0) {
        std::cout << "Netflow getaddrinfo function failed with code: " << getaddrinfo_result
               << " please check netflow_host syntax" << std::endl;
        return;
    }

    int sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);

    std::cout << "Setting reuse port" << std::endl;

    int reuse_port_optval = 1;

    auto set_reuse_port_res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse_port_optval, sizeof(reuse_port_optval));

    if (set_reuse_port_res != 0) {
        std::cout << "Cannot enable reuse port mode"<< std::endl;
        return;
    }

    // We may have custom reuse port load balancing algorithm 
    if (true) {
        std::cout << "Loading BPF to implement random UDP traffic distribution over available threads" << std::endl;

        struct sock_filter bpf_random_load_distribution[3] = {
            /* A = (uint32_t)skb[0] */
            { BPF_LD  | BPF_W | BPF_ABS, 0, 0, 0 },
            /* A = A % mod */
            { BPF_ALU | BPF_MOD, 0, 0, netflow_threads_per_port },
            /* return A */
            { BPF_RET | BPF_A, 0, 0, 0 },
        };

        struct sock_fprog bpf_programm;

        bpf_programm.len    = 3;
        bpf_programm.filter = bpf_random_load_distribution;

        // UDP support for this feature is available since Linux 4.5
        int attach_filter_result = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &bpf_programm, sizeof(bpf_programm));

        if (attach_filter_result != 0) {
            std::cout << "Can't attach reuse port BPF filter for port " << port_as_string
                   << " errno: " << errno << " error: " << strerror(errno) << std::endl;
            // It's not critical issue. We will use default distribution logic
        } else { 
            std::cout << "Successfully loaded reuse port BPF"<< std::endl;
        }
    }

    int bind_result = bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen);

    if (bind_result) {
        std::cout << "Can't bind on port: " << netflow_port << " on host " << netflow_host
               << " errno:" << errno << " error: " << strerror(errno) << std::endl;

        return;
    } else {
        std::cout << "Successful bind" << std::endl;
    }

    std::cout << "Started capture" << std::endl;

    while (true) {
        const unsigned int udp_buffer_size = 65536;
        char udp_buffer[udp_buffer_size];

        // This approach provide ability to store both IPv4 and IPv6 client's
        // addresses
        struct sockaddr_storage client_address;
        
        memset(&client_address, 0, sizeof(struct sockaddr_storage));
        socklen_t address_len = sizeof(struct sockaddr_storage);

        int received_bytes = recvfrom(sockfd, udp_buffer, udp_buffer_size, 0, (struct sockaddr*)&client_address, &address_len);

        // logger << log4cpp::Priority::ERROR << "Received " << received_bytes << " with netflow UDP server";

        if (received_bytes > 0) {
            packets_per_thread[thread_id]++;
        }
    }

    std::cout << "Netflow processing thread for " << netflow_host << ":" << netflow_port << " was finished";
    freeaddrinfo(servinfo);
}

int main() {
    std::string host =  "0.0.0.0";
    uint32_t port = 2056;

    uint32_t number_of_threads = 2;

    std::vector<std::thread> thread_group;

    for (size_t thread_id = 0; thread_id < number_of_threads; thread_id++) {
        std::thread current_thread(start_netflow_collector, thread_id, host, port, number_of_threads);
        thread_group.push_back(std::move(current_thread));
    }

    for (auto& thread: thread_group) {
        thread.join();
    }
}
