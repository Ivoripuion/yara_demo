import argparse
import concurrent.futures
import os
import yara

def read_yara(yara_path):
    """
    读取yara规则
    :param yara_path: str yara文件路径
    :return compiled_rules: List[yara object] yara规则对象列表 
    """

    compiled_rules = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for file in os.listdir(yara_path):
            if file.endswith((".yar", ".yara")):
                rule_file = os.path.join(yara_path, file)
                future = executor.submit(yara.compile, filepath=rule_file)
                compiled_rules.append(future.result())
    return compiled_rules

def match_file(file_path,rule_path):
    """
    匹配目标文件
    :param filepath: str 目标文件路径
    :return matched_rule_files: List[Tuple[str, str]] 匹配到的yara规则文件和对应的规则名称，如果没有匹配成功，返回空列表
    """

    compiled_rules = read_yara(rule_path)
    matched_rules = []
    for rule, rule_filename in zip(compiled_rules, os.listdir(rule_path)):
        matches = rule.match(file_path)
        if matches:
            for match in matches:
                matched_rules.append((rule_filename, match.rule))
    return matched_rules

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Match virus with yara rules.")
    parser.add_argument("-f","--filepath",type=str,help="病毒路径")
    parser.add_argument("-r","--ruledir",type=str,help="yara规则存放文件夹路径（文件夹下的yara规则需要以“.yar”或者“.yara”为结尾）")
    args = parser.parse_args()

    if not args.filepath:
        print("请提供文件路径！")
        exit(1)
    if not args.ruledir:
        print("请提供规则文件路径！")
        exit(1)

    matched_rules = match_file(args.filepath, args.ruledir)
    if matched_rules:
        print("匹配到以下yara规则：")
        for rule_file, rule_name in matched_rules:
            print(rule_file + " : " + rule_name)
    else:
        print("没有匹配到yara规则！")