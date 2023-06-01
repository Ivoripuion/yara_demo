#include <iostream>
#include <windows.h>
#include <yara.h>

#define RULES_DIR "D:\\workstation\\yara_demo\\yara_demo\\rules"
#define SCAN_DIR "D:\\workstation\\yara_demo\\yara_demo\\scan"

int my_callback_function(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        std::cout << "Matched!" << std::endl;
        return CALLBACK_ABORT;
    }

    if (message == CALLBACK_MSG_SCAN_FINISHED) {
        LARGE_INTEGER liFinishTime; // 定义结束时间
        QueryPerformanceCounter(&liFinishTime); // 获取结束时间
        LARGE_INTEGER liFrequency; // 计时器频率
        QueryPerformanceFrequency(&liFrequency);
        double elapsedTime = static_cast<double>(liFinishTime.QuadPart - *reinterpret_cast<LONGLONG*>(user_data)) / liFrequency.QuadPart; // 计算扫描时间
        std::cout << "Elapsed Time: " << elapsedTime << " s" << std::endl; // 输出扫描时间
        return CALLBACK_ABORT;
    }

    return CALLBACK_CONTINUE;
}

int main(int argc, char** argv)
{
    // 打开rule目录
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA((std::string(RULES_DIR) + "\\*").c_str(), &find_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open rule directory" << std::endl;
        return EXIT_FAILURE;
    }

    // 初始化Yara引擎
    int result = yr_initialize();
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to initialize Yara engine" << std::endl;
        FindClose(hFind);
        return EXIT_FAILURE;
    }

    // 创建编译器对象
    YR_COMPILER* compiler;
    result = yr_compiler_create(&compiler);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to create Yara compiler" << std::endl;
        FindClose(hFind);
        return EXIT_FAILURE;
    }

    // 遍历rule目录，读取所有规则文件
    do {
        if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::string rule_file = std::string(RULES_DIR) + "\\" + find_data.cFileName;
            HANDLE hFile = CreateFileA(rule_file.c_str(),
                GENERIC_READ,
                0,
                NULL,
                OPEN_EXISTING,
                0,
                NULL);
            if (hFile == INVALID_HANDLE_VALUE) {
                std::cerr << "Failed to open rule file for reading: " << rule_file << std::endl;
                continue;
            }
            result = yr_compiler_add_fd(compiler, hFile, NULL, NULL);
            if (result != ERROR_SUCCESS) {
                std::cerr << "Failed to add file contents to Yara compiler: " << rule_file << "\nError Code:" << result << std::endl;
                CloseHandle(hFile);
                continue;
            }
        }
    } while (FindNextFileA(hFind, &find_data));

    FindClose(hFind);

    // 编译规则
    YR_RULES* rules;
    result = yr_compiler_get_rules(compiler, &rules);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to compile Yara rules" << std::endl;
        yr_compiler_destroy(compiler);
        return EXIT_FAILURE;
    }

    // 扫描scan目录下的所有文件
    hFind = FindFirstFileA((std::string(SCAN_DIR) + "\\*").c_str(), &find_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open scan directory" << std::endl;
        yr_rules_destroy(rules);
        yr_compiler_destroy(compiler);
        yr_finalize();
        return EXIT_FAILURE;
    }

    LARGE_INTEGER liStartTime; // 定义开始时间
    QueryPerformanceCounter(&liStartTime); // 获取开始时间
    do {
        if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::string scan_file = std::string(SCAN_DIR) + "\\" + find_data.cFileName;
            result = yr_rules_scan_file(rules, scan_file.c_str(), SCAN_FLAGS_FAST_MODE, my_callback_function, &liStartTime.QuadPart, 1000); // 将开始时间指针传递给回调函数
            if (result != ERROR_SUCCESS) {
                std::cerr << "Failed to scan file with Yara rules: " << scan_file << std::endl;
                continue;
            }
        }
    } while (FindNextFileA(hFind, &find_data));

    FindClose(hFind);

    // 完成后释放内存
    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();

    return EXIT_SUCCESS;
}
