#!/usr/bin/env python3

import re
import subprocess
import sys
import argparse

def decode_symbol(symbol):
    """使用 c++filt 解码 C++ 符号名称"""
    try:
        # 调用 c++filt，传入符号名称
        result = subprocess.run(['c++filt', symbol], 
                              capture_output=True, 
                              text=True, 
                              check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return None  # 解码失败返回 None
    except FileNotFoundError:
        print("Error: c++filt not found. Please ensure it is installed.", file=sys.stderr)
        sys.exit(1)

def process_input(input_source, output_file):
    """处理输入，匹配正则表达式并将成功匹配的符号解码后写入文件"""
    # 正则表达式：匹配以 0000000000 开头，包含 C2 的字符串
    pattern = r'^0000000000.*C2'
    
    # 编译正则表达式
    regex = re.compile(pattern)
    
    # 打开输出文件
    with open(output_file, 'w') as out_f:
        # 逐行处理输入
        for line in input_source:
            line = line.strip()  # 去除首尾空白
            if regex.match(line):
                decoded = decode_symbol(line)
                if decoded:  # 仅当解码成功时写入
                    out_f.write(f"Matched symbol: {line}\n")
                    out_f.write(f"Decoded: {decoded}\n")
                    out_f.write("-" * 80 + "\n")
            # 未匹配的字符串被忽略，不输出

def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="Match and decode C++ symbols starting with '0000000000' and containing 'C2', output to file.")
    parser.add_argument('input_file', nargs='?', 
                        help="Input file containing symbols (default: read from stdin)")
    # parser.add_argument('-o', '--output', required=True,
    #                     help="Output file for matched and decoded symbols")
    args = parser.parse_args()

    # 根据输入参数选择输入源
    if args.input_file:
        try:
            with open(args.input_file, 'r') as f:
                process_input(f, "result.txt")
        except FileNotFoundError:
            print(f"Error: File '{args.input_file}' not found.", file=sys.stderr)
            sys.exit(1)
    else:
        print("Reading from stdin (press Ctrl+D to end input on Unix, Ctrl+Z on Windows):")
        process_input(sys.stdin, "result.txt")

if __name__ == "__main__":
    main()