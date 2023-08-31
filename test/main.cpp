#include <Windows.h>
#include <iostream>
#include <vector>
#include <tuple>

std::pair<const uint8_t*, SIZE_T> getProcessMemory(DWORD pid) {
    // 打开进程
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == nullptr) {
        std::cerr << "Failed to open process: " << GetLastError() << std::endl;
        return std::make_pair(nullptr, 0);
    }

    // 获取进程内存信息
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    MEMORY_BASIC_INFORMATION mbi;
    std::vector<uint8_t> buffer;

    for (LPVOID addr = si.lpMinimumApplicationAddress; addr < si.lpMaximumApplicationAddress;) {
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == 0) {
            std::cerr << "Failed to query memory: " << GetLastError() << std::endl;
            break;
        }

        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE) && !(mbi.Protect & PAGE_GUARD)) {
            std::vector<uint8_t> region(mbi.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, addr, &region[0], mbi.RegionSize, &bytesRead)) {
                buffer.insert(buffer.end(), region.begin(), region.begin() + bytesRead);
            }
        }

        addr = (LPBYTE)addr + mbi.RegionSize;
    }

    // 关闭进程句柄
    CloseHandle(hProcess);

    // 创建返回值
    uint8_t* resultBuffer = new uint8_t[buffer.size()];
    std::copy(buffer.begin(), buffer.end(), resultBuffer);
    return std::make_pair(resultBuffer, buffer.size());
}

int main() {
    DWORD pid;
    std::cout << "Enter the PID of the process: ";
    std::cin >> pid;

    auto result = getProcessMemory(pid);
    const uint8_t* buffer = result.first;
    SIZE_T bytesRead = result.second;

    if (buffer != nullptr) {
        std::cout << "Read " << bytesRead << " bytes from process memory." << std::endl;
        delete[] buffer;
    }
    else {
        std::cout << "Failed to read process memory." << std::endl;
    }

    return 0;
}