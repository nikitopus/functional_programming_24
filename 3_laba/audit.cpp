#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <map>
#include "constant.h"
#include <sstream>
#include <iomanip>

using namespace std;
namespace fs = std::filesystem;

// Получение текущего времени
string current_time() {
    time_t now = time(0);
    tm* time_struct = localtime(&now);

    ostringstream line_stream;
    line_stream << put_time(time_struct, "%d.%m.%Y %H:%M:%S");
    return line_stream.str();
}

// Проверка размера файла и архивирование
void check_log_size(const string &log_file) {
    const size_t MAX_SIZE = 1024 * 1024; // 1 MB
    if (fs::file_size(log_file) > MAX_SIZE) {
        string archive_name = log_file + ".bak";
        fs::rename(log_file, archive_name);
    }
}

// Отправка уведомлений по email
void send_email(const string &message) {
    FILE *mail = popen("/usr/sbin/sendmail -t", "w");
    if (mail) {
        fprintf(mail, "To: nikitopus05@mail.ru\n");
        fprintf(mail, "Subject: Audit Notification\n\n");
        fprintf(mail, "%s\n", message.c_str());
        pclose(mail);
    }
}

// Запись системных вызовов
void write_system(unsigned long long system_code, ofstream &file, int pid) {
    file << pid << ": ";
    file << current_time() << ": ";
    file << system_names[system_code] << " code=" << system_code << endl;
}

// Запись команды
void write_command(const char* line, ofstream &file, int pid) {
    file << pid << ": ";
    file << current_time() << ": ";
    file << line << endl;
}

int main(int argc, char** argv) {
    setlogmask(LOG_UPTO(LOG_NOTICE));
    if (argc != 2) {
        syslog(LOG_INFO, "wrong arguments");
        return -1;
    }

    // Ограничение привилегий
    seteuid(getuid());
    setegid(getgid());

    int pid = stoi(argv[1]);
    const string log_file = "logs.log";
    check_log_size(log_file);
    ofstream file(log_file, ios::app);

    write_command("ptrace is attached", file, pid);
    ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
    if (errno == -1) {
        send_email("Error attaching to process.");
        return errno;
    }

    write_command("ptrace set options", file, pid);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
    if (errno == -1) {
        return errno;
    }

    int status;
    waitpid(pid, &status, 0);
    user_regs_struct regs;
    while (WIFSTOPPED(status)) {
        ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
        if (errno == -1) return -1;
        waitpid(pid, &status, 0);
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        if (errno == -1) {
            return errno;
        }
        write_system(regs.orig_rax, file, pid);
    }

    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    write_command("ptrace finished listening system calls", file, pid);

    send_email("Audit completed successfully.");
    return 0;
}
