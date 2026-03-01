# !/usr/bin/env python3
# -*- coding: utf-8 -*-
#最近由于很多中木马病毒，仅对该木马做检测清除
'''
new Env('病毒检测清除');
8 8 29 2 * jd_clean_muma.py
'''
import os
import shutil
import subprocess
import sys

def get_malicious_pids(process_name):
    try:
        result = subprocess.run(['pgrep', '-f', process_name], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip().split('\n')
    except Exception:
        pass
    return []

def clean_config_file(config_file_path):
    if not os.path.exists(config_file_path):
        return False

    # 备份原始文件
    backup_file_path = f"{config_file_path}.bak"
    try:
        shutil.copyfile(config_file_path, backup_file_path)
    except Exception as e:
        print(f"警告：备份文件失败: {e}")

    try:
        with open(config_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"错误：读取文件 {config_file_path} 失败: {e}")
        return False

    malicious_keywords = [
        ".fullgc",
        "551911.xyz",
        "fullgc-linux",
        "fullgc-macos",
        "QL_DIR:-/ql}/data/db",
        "chmod",
        "curl",
        "{",
        "}",
        "nohup \"$b\" >/dev/null 2>&1 &"
    ]

    new_lines = []
    removed_count = 0
    for line in lines:
        is_malicious = False
        for keyword in malicious_keywords:
            if keyword in line:
                is_malicious = True
                break
        
        if is_malicious:
            removed_count += 1
            print(f"发现并移除恶意行: {line.strip()}")
        else:
            new_lines.append(line)

    if removed_count > 0:
        try:
            temp_file_path = f"{config_file_path}.tmp"
            with open(temp_file_path, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            shutil.move(temp_file_path, config_file_path)
            print(f"成功从 {config_file_path} 中清除 {removed_count} 行恶意代码。")
            return True
        except Exception as e:
            print(f"错误：写入或替换文件 {config_file_path} 失败: {e}")
    return False

if __name__ == "__main__":
    MALICIOUS_PROCESS_NAME = ".fullgc"
    MALICIOUS_FILE = "/ql/data/db/.fullgc"

    print(f"--- 开始木马检测 [{MALICIOUS_PROCESS_NAME}] ---")

    pids = get_malicious_pids(MALICIOUS_PROCESS_NAME)
    if not pids:
        print(f"未发现名为 '{MALICIOUS_PROCESS_NAME}' 的木马进程。请注意安全，不要开到公网访问，不要弱密码！！！")
        sys.exit(0)

    print(f"‼️警告：发现 {len(pids)} 个木马进程，PID 列表: {', '.join(pids)}")
    print(f"正在强制终止这些进程...")
    try:
        subprocess.run(['pkill', '-9', '-f', MALICIOUS_PROCESS_NAME], capture_output=True)
        print(f"✅已成功终止所有木马进程。")
    except Exception as e:
        print(f"终止进程时发生错误: {e}")

    if os.path.exists(MALICIOUS_FILE):
        print(f"‼️发现恶意文件 '{MALICIOUS_FILE}'，正在删除...")
        try:
            os.remove(MALICIOUS_FILE)
            print(f"✅恶意文件 '{MALICIOUS_FILE}' 已删除。")
        except Exception as e:
            print(f"警告：无法删除恶意文件: {e}")

    print(f"正在清理配置文件中的持久化代码...")
    config_paths = ["/ql/data/config/config.sh", "/ql/config/config.sh"]
    for path in config_paths:
        if os.path.exists(path):
            clean_config_file(path)
    print("正在扫描 /ql/data/db/ 目录下的其他可疑隐藏文件...")
    if os.path.exists("/ql/data/db/"):
        found_suspicious = False
        for root, _, files in os.walk("/ql/data/db/"):
            for file in files:
                if file.startswith('.') and not file.endswith('.db'):
                    file_path = os.path.join(root, file)
                    if os.access(file_path, os.X_OK):
                        print(f"警告：发现可疑隐藏执行文件: {file_path}")
                        found_suspicious = True
        if not found_suspicious:
            print("未发现其他可疑隐藏文件。")

    print("--- 木马清理过程全部完成 ---")
    print("🚫🚫面板不要开到公网上访问，等待漏洞修复，以免再次中招！！！修改登录密码，不要弱密码")

