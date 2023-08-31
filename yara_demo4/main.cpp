#include <iostream>
#include <windows.h>
#include <yara.h>

#define RULES_FILE "D:\\workstation\\yara_demo\\yara_demo\\test.yar"
#define PROCESS_NAME "notepad.exe"

int my_callback_function(int message, void* message_data, void* user_data)
{
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        std::cout << "Matched!" << std::endl;
        return CALLBACK_ABORT;
    }

    if (message == CALLBACK_MSG_SCAN_FINISHED) {
        std::cout << "Not Matched!" << std::endl;
        return CALLBACK_ABORT;
    }

    return CALLBACK_CONTINUE;
}

int main(int argc, char** argv)
{
    // ��ʼ��Yara����
    int result = yr_initialize();
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to initialize Yara engine" << std::endl;
        return EXIT_FAILURE;
    }

    // ��������������
    YR_COMPILER* compiler;
    result = yr_compiler_create(&compiler);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to create Yara compiler" << std::endl;
        return EXIT_FAILURE;
    }

    // ��rule�ļ�
    HANDLE hFile = CreateFileA(RULES_FILE,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open rule file for reading" << std::endl;
        return EXIT_FAILURE;
    }

    // �������
    result = yr_compiler_add_fd(compiler, hFile, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to add file contents to Yara compiler" << "\nError Code:" << result << std::endl;
        CloseHandle(hFile);
        return EXIT_FAILURE;
    }

    // �������
    YR_RULES* rules;
    result = yr_compiler_get_rules(compiler, &rules);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to compile Yara rules" << std::endl;
        CloseHandle(hFile);
        return EXIT_FAILURE;
    }

    // ��ȡ���̾��
    HANDLE hProcess = NULL;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (strcmp(pe32.szExeFile, PROCESS_NAME) == 0) {
                hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process" << std::endl;
        return EXIT_FAILURE;
    }

    // ɨ������ڴ�
    result = yr_rules_scan_process(rules, hProcess, SCAN_FLAGS_FAST_MODE, my_callback_function, NULL, 1000);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to scan memory with Yara rules" << std::endl;
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // ��ɺ��ͷ��ڴ�
    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();
    CloseHandle(hFile);
    CloseHandle(hProcess);

    return EXIT_SUCCESS;
}