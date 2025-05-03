#!/bin/bash

# 设置目标文件夹
TARGET_DIR="/home/llh/sba/dynamic"

# 创建目标文件夹，如果不存在的话
mkdir -p "$TARGET_DIR"

# 进入根目录
cd /home/llh/spec-orig/benchspec/CPU2006/

# 遍历每个子目录
for dir in */; do
    # 检查当前是否是目录
    if [ -d "$dir" ]; then
        # 进入该子目录
        cd "$dir"

        # 检查是否有run目录，并进入
        if [ -d "exe" ]; then
            cd "exe"

            # 查找并复制所有以 .tbdump 结尾的文件
            for file in *.dbt6_dyn_o3; do
               # 检查是否有匹配的文件
               if [ -f "$file" ]; then
                     $sba "$file"
               fi
            done
            # 获取文件名（去除扩展名）
            base_name=$(basename "$file" .dbt6_dyn_o3)
            
            # 复制result.json到目标目录，并重命名为 $base_name.json
            mv /home/llh/sba/result.json "$TARGET_DIR/$base_name.json"            # 返回到当前子目录
            cd ..
        fi

        # 返回到根目录
        cd ..
    fi
done

echo "所有文件已复制到 $TARGET_DIR"
