#include <iostream>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <ctime>
#include <csignal>
#include <syslog.h>
#include <unistd.h>
#include <thread>
#include <map>
#include <string>
#include <stdexcept>
#include <sstream>

namespace fs = std::filesystem;

bool running = true;

void signalHandler(int signum) {
    if (signum == SIGTERM || signum == SIGINT) {
        syslog(LOG_INFO, "Received termination signal. Stopping daemon.");
        running = false;
    }
}

std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time), "%Y%m%d_%H%M%S");
    return oss.str();
}

class Config {
public:
    std::string sourceDir;
    std::string backupDir;
    int backupFrequency;

    void loadConfig(const std::string& filename) {
        std::ifstream configFile(filename);
        if (!configFile.is_open()) throw std::runtime_error("Unable to open config file.");

        std::string line;
        while (std::getline(configFile, line)) {
            std::istringstream iss(line);
            std::string key, value;
            if (std::getline(iss, key, '=') && std::getline(iss, value)) {
                if (key == "sourceDir") sourceDir = value;
                else if (key == "backupDir") backupDir = value;
                else if (key == "backupFrequency") backupFrequency = std::stoi(value);
            }
        }
    }
};

void backupFiles(const std::string& sourceDir, const std::string& backupDir) {
    std::string timestamp = getCurrentTimestamp();
    std::string backupDirWithTimestamp = backupDir + "/" + timestamp;

    fs::create_directories(backupDirWithTimestamp);
    for (const auto& entry : fs::directory_iterator(sourceDir)) {
        if (fs::is_regular_file(entry.path())) {
            fs::copy(entry.path(), backupDirWithTimestamp + "/" + entry.path().filename().string(), fs::copy_options::overwrite_existing);
        }
    }
}

int main() {
    Config config;
    try {
        config.loadConfig("/home/nik/linux_system_programming/2_laba/backup_config.ini");
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "Failed to fork." << std::endl;
        return EXIT_FAILURE;
    }
    if (pid > 0) exit(EXIT_SUCCESS);  // Родительский процесс завершает работу

    setsid();  // Создаем новый сеанс
    signal(SIGTERM, signalHandler);
    signal(SIGINT, signalHandler);

    openlog("backupd", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "Backup daemon started.");

    while (running) {
        backupFiles(config.sourceDir, config.backupDir);
        syslog(LOG_INFO, "Backup completed.");
        std::this_thread::sleep_for(std::chrono::minutes(config.backupFrequency));
    }

    syslog(LOG_INFO, "Backup daemon stopped.");
    closelog();
    return EXIT_SUCCESS;
}
