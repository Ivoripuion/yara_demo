#include <iostream>
#include <stdlib.h>
#include <string>
using namespace std;

#define RULES_FILE "D:\\workstation\\yara_demo\\yara_demo\\test.yar"
#define VIRUS_FILE "D:\\workstation\\yara_demo\\yara_demo\\test.txt"

int main() {
    string rule_file = RULES_FILE;
    string virus_file = VIRUS_FILE;
    string cmdline = "yara " + rule_file + " " + virus_file;
    system(cmdline.c_str()); //执行 yara 扫描
    return 0;
}