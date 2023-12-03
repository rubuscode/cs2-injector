#include <iostream>
#include <thread>
#include <chrono>
#include <filesystem>
#include "injector/bypass.h"

int main() {
    SetConsoleTitleA("ver. 0.1 | coded by rubus");
    while (true) {
        try {
            std::string dllPath;
            std::cout << "dll path: ";
            std::getline(std::cin, dllPath);

            std::filesystem::path pathObj(dllPath);

            if (!std::filesystem::exists(pathObj) || pathObj.extension() != ".dll") {
                std::cout << "invalid or non-existent DLL path.\n";
                std::this_thread::sleep_for(std::chrono::milliseconds(350));
                system("CLS");
                continue;
            }

            Injector::Inject(dllPath);

            std::this_thread::sleep_for(std::chrono::seconds(3));
            break;
        }
        catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(3));
            return 1;
        }
    }
    return 0;
}
