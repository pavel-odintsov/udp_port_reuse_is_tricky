#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <array>

#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <linux/filter.h>

std::array<uint64_t, 512> packets_per_thread;

// Set reuse_addr flag for socket as workaround for inability to add sockets into reuse_port group after we assign BPF for it
bool set_reuse_addr_flag = false;

// In this case we will follow documented behaviour which sadly does not work without reuse_addr
bool assign_bpf_for_each_socket_in_reuse_port_group = false;

// In this case we assign BPF after we create reuse port group and did bind
bool assign_bpf_after_reuse_port_group_creation = true;

// Loads BPF for socket
bool load_bpf(int sockfd, uint32_t netflow_threads_per_port) {
    std::cout << "Loading BPF to implement random UDP traffic distribution over available threads" << std::endl;

    struct sock_filter bpf_random_load_distribution[3] = {
        /* Load random to A */
        { BPF_LD  | BPF_W | BPF_ABS,  0,  0, 0xfffff038 },
        /* A = A % mod */
        { BPF_ALU | BPF_MOD, 0, 0, netflow_threads_per_port },
        /* return A */
        { BPF_RET | BPF_A, 0, 0, 0 },
    };

    // There is an alternative way to pass number of therads
    bpf_random_load_distribution[1].k = uint32_t(netflow_threads_per_port);

    struct sock_fprog bpf_programm;

    bpf_programm.len    = 3;
    bpf_programm.filter = bpf_random_load_distribution;

    // UDP support for this feature is available since Linux 4.5
    int attach_filter_result = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &bpf_programm, sizeof(bpf_programm));

    if (attach_filter_result != 0) {
        std::cout << "Can't attach reuse port BPF filter " << " errno: " << errno << " error: " << strerror(errno) << std::endl;
        return false;
    } 

    std::cout << "Successfully loaded reuse port BPF"<< std::endl;
    
    return true;
}


bool create_and_bind_socket(std::size_t thread_id, const std::string& netflow_host, unsigned int netflow_port, uint32_t netflow_threads_per_port, int& sockfd) {
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
        return false;
    }

    sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);

    std::cout << "Setting reuse port" << std::endl;

    int reuse_port_optval = 1;

    auto set_reuse_port_res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse_port_optval, sizeof(reuse_port_optval));

    if (set_reuse_port_res != 0) {
        std::cout << "Cannot enable reuse port mode"<< std::endl;
        return false;
    }

    if (set_reuse_addr_flag) {
        auto set_reuse_addr_res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse_port_optval, sizeof(reuse_port_optval));

	    if (set_reuse_addr_res != 0) {
	        std::cout << "Cannot enable reuse port mode"<< std::endl;
	        return false;
	    }
    }

    // We may have custom reuse port load balancing algorithm 
    if (assign_bpf_for_each_socket_in_reuse_port_group) {
        bool bpf_result = load_bpf(sockfd, netflow_threads_per_port);
    
        if (!bpf_result) {
            std::cout << "Cannot load BPF" << std::endl;
        }
    }

    int bind_result = bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen);

    if (bind_result) {
        std::cout << "Can't bind on port: " << netflow_port << " on host " << netflow_host
               << " errno:" << errno << " error: " << strerror(errno) << std::endl;

        return false;;
    }

    std::cout << "Successful bind" << std::endl;

    // Free up memory for server information structure
    freeaddrinfo(servinfo);

    return true;
}

void capture_traffic_from_socket(int sockfd, std::size_t thread_id) {
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
}

void print_speed(uint32_t number_of_thread) {
    std::array<uint64_t, 512> packets_per_thread_previous = packets_per_thread;

    std::cout <<"Thread ID" << "\t" << "UDP packet / second" << std::endl; 

    while (true) {
	    std::this_thread::sleep_for(std::chrono::seconds(1));

	    for (uint32_t i = 0; i < number_of_thread; i++) {
            std::cout << "Thread " << i << "\t" << packets_per_thread[i] - packets_per_thread_previous[i] << std::endl;
	    }

	    packets_per_thread_previous = packets_per_thread;
    }
}

int main() {
    std::string host =  "0.0.0.0";
    uint32_t port = 2055;

    uint32_t number_of_threads = 2;

    class worker_data_t {
        public:
            int socket_fd = 0;
            size_t thread_id = 0;
    };

    std::vector<worker_data_t> workers;;

    std::vector<std::thread> thread_group;

    for (size_t thread_id = 0; thread_id < number_of_threads; thread_id++) {
        int socket_fd = 0;

        bool result = create_and_bind_socket(thread_id, host, port, number_of_threads, socket_fd);

        if (!result) {
            std::cout << "Cannot create / bind socket" << std::endl;
            exit(1);
        }

        worker_data_t worker_data;
        worker_data.socket_fd = socket_fd;
        worker_data.thread_id = thread_id;

        workers.push_back(worker_data);
    }

    std::cout << "Starting packet capture" << std::endl;
    for (const auto& worker_data: workers) {
        if (assign_bpf_after_reuse_port_group_creation) {
            bool bpf_result = load_bpf(worker_data.socket_fd, number_of_threads);

            if (!bpf_result) {
                std::cout << "Cannot load BPF" << std::endl;
                exit(1);
            }
        }
            
        std::thread current_thread(capture_traffic_from_socket, worker_data.socket_fd, worker_data.thread_id);
        thread_group.push_back(std::move(current_thread));
    }

    // Add some delay to be sure that both threads started
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Start speed printer
    std::thread speed_printer(print_speed, number_of_threads);

    for (auto& thread: thread_group) {
        thread.join();
    }
}
