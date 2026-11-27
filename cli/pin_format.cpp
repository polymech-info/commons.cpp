// Tiny smoke tool for SPKI pin formatting (no commons umbrella, no curl).
#include "pm/commons/net/tls.hpp"

#include <iostream>
#include <string>

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr << "usage: pm-commons-pin <64-hex-spki>\n";
        return 2;
    }
    const std::string hex = argv[1];
    if (!pm::commons::net::spki_hex_ok(hex)) {
        std::cout << "{\"ok\":false,\"code\":\"EPIN\",\"error\":\"the certificate pin is not valid\"}\n";
        return 1;
    }
    std::string err;
    const auto pin = pm::commons::net::spki_pin_curl(hex, err);
    if (pin.empty()) {
        std::cout << "{\"ok\":false,\"code\":\"EPIN\",\"error\":\""
                  << (err.empty() ? "the certificate pin is not valid" : err) << "\"}\n";
        return 1;
    }
    std::cout << "{\"ok\":true,\"pin\":\"" << pin << "\",\"hex\":\"" << hex << "\"}\n";
    return 0;
}
