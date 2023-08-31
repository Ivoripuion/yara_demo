#include <iostream>
#include <windows.h>
#include <yara.h>

#define RULES_FILE "D:\\workstation\\yara_demo\\yara_demo\\test.yar"
#define VIRUS_FILE "D:\\workstation\\yara_demo\\yara_demo\\test.txt"

int my_callback_function(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
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
    // 打开rule文件
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

    //打开样本文件
    HANDLE vFile = CreateFileA(VIRUS_FILE,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (vFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open virus file for reading" << std::endl;
        return EXIT_FAILURE;
    }

    // 初始化Yara引擎
    int result = yr_initialize();
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to initialize Yara engine" << std::endl;
        CloseHandle(hFile);
        return EXIT_FAILURE;
    }

    // 创建编译器对象
    YR_COMPILER* compiler;
    result = yr_compiler_create(&compiler);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to create Yara compiler" << std::endl;
        CloseHandle(hFile);
        return EXIT_FAILURE;
    }

    //载入规则
    result = yr_compiler_add_fd(compiler, hFile, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to add file contents to Yara compiler" << "\nError Code:" << result << std::endl;
        CloseHandle(hFile);
        return EXIT_FAILURE;
    }
    

    // 编译规则
    YR_RULES* rules;
    result = yr_compiler_get_rules(compiler, &rules);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to compile Yara rules" << std::endl;
        CloseHandle(hFile);
        return EXIT_FAILURE;
    }

    // 执行病毒扫描
    result = yr_rules_scan_fd(rules,vFile,SCAN_FLAGS_FAST_MODE,my_callback_function,NULL,1000);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to scan memory with Yara rul es" << std::endl;
        CloseHandle(hFile);
        return EXIT_FAILURE;
    }

    // 完成后释放内存
    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();
    CloseHandle(hFile);
    CloseHandle(vFile);

    return EXIT_SUCCESS;
}
