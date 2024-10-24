#include <iostream>
#include <boost/asio.hpp>
#include <thread>
#include <vector>
#include <future>
#include <fstream>
#include <mutex>
#include <unordered_map>
#include <sstream>
#include <cstdlib>  // For system commands (ping)
#include <chrono>   // For timing

// Mutex for synchronizing file writes
std::mutex fileMutex;
std::mutex progressMutex;

int IpNums = 4;

// Function to check if a port is open
bool isPortOpen(boost::asio::io_service& io_service, const std::string& ip, int port) {
    using boost::asio::ip::tcp;
    tcp::socket socket(io_service);
    tcp::endpoint endpoint(boost::asio::ip::address::from_string(ip), port);
    boost::system::error_code ec;
    socket.connect(endpoint, ec);
    return !ec;  // Return true if the port is open
}

// Reading checked ports from file
std::unordered_map<int, bool> readCheckedPortsFromFile(const std::string& filename) {
    std::unordered_map<int, bool> checkedPorts;
    std::ifstream infile(filename);
    std::string line;
    int port;
    std::string status;

    while (std::getline(infile, line)) {
        std::istringstream iss(line);
        if (iss >> port >> status) {
            checkedPorts[port] = (status == "open");
        }
    }
    return checkedPorts;
}

// Writing the status of a port to the common file
void writePortStatusToFile(const std::string& filename, int port, bool isOpen) {
    std::lock_guard<std::mutex> lock(fileMutex);
    std::ofstream outfile(filename, std::ios_base::app);
    if (outfile.is_open()) {
        outfile << port << " " << (isOpen ? "open" : "closed") << std::endl;
    }
}

// Writing the open port to a separate file
void writeOpenPortToFile(const std::string& openFilename, int port) {
    std::lock_guard<std::mutex> lock(fileMutex);
    std::ofstream outfile(openFilename, std::ios_base::app);
    if (outfile.is_open()) {
        outfile << port << std::endl;  // Write only the port number
    }
}

// Function to display a progress bar
void displayProgressBar(const std::string& ip, int completed, int total, const std::string& action, int line) {
    std::lock_guard<std::mutex> lock(progressMutex);
    int barWidth = 50;  // Width of the progress bar
    float progress = (float)completed / total;

    // Move cursor to the specific line (using ANSI escape code)
    std::cout << "\033[" << line << ";1H";  // Move to specified line, column 1

    // Display progress bar
    std::cout << "[" << ip << "] [";
    int pos = barWidth * progress;
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << int(progress * 100.0) << "% " << action;

    // Print new line after completion
    if (completed == total) {
        std::cout << std::endl;
    }
}

// Scanning ports in a given range
void scanPorts(const std::string& ip, int startPort, int endPort, int line) {
    std::string filename = ip + ".txt";        // File for all ports
    std::string openFilename = ip + "_Open.txt"; // File only for open ports
    std::unordered_map<int, bool> checkedPorts = readCheckedPortsFromFile(filename);  // Read checked ports

    boost::asio::io_service io_service;
    int totalPorts = endPort - startPort + 1;
    std::vector<std::future<void>> futures;

    for (int port = startPort; port <= endPort; ++port) {
        // Skip already checked ports
        if (checkedPorts.find(port) != checkedPorts.end()) {
            continue;  // Skip outputting messages for already checked ports
        }

        // Create a future for each port scan
        futures.push_back(std::async(std::launch::async, [&, port]() {
            try {
                bool isOpen = isPortOpen(io_service, ip, port);

                // Write the port status to the common file
                writePortStatusToFile(filename, port, isOpen);

                // If the port is open, write it to the separate file
                if (isOpen) {
                    writeOpenPortToFile(openFilename, port);
                }
            }
            catch (const std::exception& e) {
                // Handle exceptions (e.g., connection timeout)
                std::lock_guard<std::mutex> lock(fileMutex);
                std::cerr << "Error scanning port " << port << " on IP " << ip << ": " << e.what() << std::endl;
            }

            // Update progress bar
            displayProgressBar(ip, port - startPort + 1, totalPorts, "Scanning ports...", line);
            }));
    }

    // Wait for all port scan futures to complete
    for (auto& f : futures) {
        f.get();
    }

    std::cout << "Port scanning completed for range " << startPort << " to " << endPort << " on IP " << ip << std::endl;
}

// Getting active devices in the network via ping
std::vector<std::string> getActiveDevicesInNetwork(const std::string& subnet) {
    std::vector<std::string> activeDevices;
    std::vector<std::future<void>> futures; // Store futures for async pings

    for (int i = 1; i <= 254; ++i) {
        std::string ip = subnet + "." + std::to_string(i);
#ifdef _WIN32  // If compiling under Windows
        std::string command = "ping -n 1 -w 1000 " + ip + " > nul";  // Windows command
#else
        std::string command = "ping -c 1 -W 1 " + ip + " > /dev/null";  // Linux/macOS command
#endif

        // Launch a ping in a separate thread
        futures.push_back(std::async(std::launch::async, [&, ip, command]() {
            if (std::system(command.c_str()) == 0) {
                IpNums += 1;
                std::lock_guard<std::mutex> lock(progressMutex);
                activeDevices.push_back(ip);  // Device responded to ping
            }
            }));
    }

    // Wait for all ping futures to complete
    for (auto& f : futures) {
        f.get();
    }

    return activeDevices;
}

// Getting the local IP address using Boost.Asio
std::string getLocalIPAddress() {
    boost::asio::io_service io_service;
    boost::asio::ip::tcp::resolver resolver(io_service);
    boost::asio::ip::tcp::resolver::query query(boost::asio::ip::host_name(), "");
    boost::asio::ip::tcp::resolver::iterator it = resolver.resolve(query);

    while (it != boost::asio::ip::tcp::resolver::iterator()) {
        boost::asio::ip::tcp::endpoint ep = *it++;
        if (ep.address().is_v4()) {
            return ep.address().to_string();  // Return the first found IPv4 address
        }
    }
    return "127.0.0.1";  // Return localhost if no IPv4 address is found
}

// Getting the subnet based on the local IP address
std::string getSubnet(const std::string& ip) {
    size_t pos = ip.rfind('.');
    return (pos == std::string::npos) ? ip : ip.substr(0, pos);
}

int main() {
    // Clear the console at the beginning
    //clearScreen();

    // Get the local IP address
    std::string ip = getLocalIPAddress();

    // Determine the subnet
    std::string subnet = getSubnet(ip);
    std::cout << "Scanning subnet: " << subnet << ".0/24" << std::endl;

    // Get active devices in the network
    std::vector<std::string> activeDevices = getActiveDevicesInNetwork(subnet);

    // Get the number of threads based on CPU cores
    unsigned int numThreads = std::thread::hardware_concurrency();
    std::cout << "Using " << numThreads << " threads for scanning." << std::endl;

    // Define the port range to scan (1-65535)
    int startPort = 1;
    int endPort = 65535;

    // Create threads for port scanning on all active devices
    std::vector<std::future<void>> futures;
    int line = IpNums;  // Start printing progress bars from line 1 (1-based index)

    for (const auto& deviceIP : activeDevices) {
        std::cout << "Scanning IP: " << deviceIP << std::endl; // Print device IP
        // Launch a thread to scan ports on each device
        futures.push_back(std::async(std::launch::async, [deviceIP, startPort, endPort, line]() {
            scanPorts(deviceIP, startPort, endPort, line);
            }));
        line++;  // Increment line number for next device
    }

    // Wait for all thread futures to complete
    for (auto& f : futures) {
        f.get();
    }

    std::cout << "Scanning completed for all devices." << std::endl;

    return 0;
}
