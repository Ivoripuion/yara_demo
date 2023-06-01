#include <iostream>
#include <windows.h>
#include <yara.h>
#include <vector>
#include <thread>
#include <mutex>

#define RULES_DIR "D:\\workstation\\yara_demo\\yara_demo\\rules"
#define SCAN_DIR "D:\\workstation\\yara_demo\\yara_demo\\scan"

std::mutex m; // 创建互斥锁
std::vector<std::string> scan_files; // 用于保存扫描的文件列表

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

void scan_file(YR_RULES* rules, const std::string& file_path, LONGLONG start_time)
{
    std::lock_guard<std::mutex> lock(m); // 加锁
    int result = yr_rules_scan_file(rules, file_path.c_str(), SCAN_FLAGS_FAST_MODE, my_callback_function, &start_time, 1000); // 将开始时间指针传递给回调函数
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to scan file with Yara rules: " << file_path << std::endl;
        return;
    }
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

    // 扫描scan目录下的所有文件并保存到扫描列表中
    hFind = FindFirstFileA((std::string(SCAN_DIR) + "\\*").c_str(), &find_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open scan directory" << std::endl;
        yr_rules_destroy(rules);
        yr_compiler_destroy(compiler);
        yr_finalize();
        return EXIT_FAILURE;
    }

    do {
        if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::string scan_file = std::string(SCAN_DIR) + "\\" + find_data.cFileName;
            scan_files.push_back(scan_file); // 保存到扫描列表中
        }
    } while (FindNextFileA(hFind, &find_data));

    FindClose(hFind);

    LARGE_INTEGER liStartTime; // 定义开始时间
    QueryPerformanceCounter(&liStartTime); // 获取开始时间

    // 创建多个线程，每个线程扫描一个文件
    std::vector<std::thread> threads;
    for (const auto& file_path : scan_files) {
        threads.emplace_back(scan_file, rules, file_path, liStartTime.QuadPart);
    }

    // 等待所有线程执行完毕
    for (auto& thread : threads) {
        thread.join();
    }

    // 完成后释放内存
    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();

    return EXIT_SUCCESS;
}
