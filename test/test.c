#include <stdio.h>

int main() {
    int choice;
    
    // 提示用户输入一个数字（1到20之间）
    printf("请输入一个数字 (1-20): ");
    scanf("%d", &choice);
    
    // 使用switch语句处理不同的选择
    switch (choice) {
        case 1:
            printf("你选择了操作1\n");
            break;
        case 2:
            printf("你选择了操作2\n");
            break;
        case 3:
            printf("你选择了操作3\n");
            break;
        case 4:
            printf("你选择了操作4\n");
            break;
        case 5:
            printf("你选择了操作5\n");
            break;
        case 6:
            printf("你选择了操作6\n");
            break;
        case 7:
            printf("你选择了操作7\n");
            break;
        case 8:
            printf("你选择了操作8\n");
            break;
        case 9:
            printf("你选择了操作9\n");
            break;
        case 10:
            printf("你选择了操作10\n");
            break;
        case 11:
            printf("你选择了操作11\n");
            break;
        case 12:
            printf("你选择了操作12\n");
            break;
        case 13:
            printf("你选择了操作13\n");
            break;
        case 14:
            printf("你选择了操作14\n");
            break;
        case 15:
            printf("你选择了操作15\n");
            break;
        case 16:
            printf("你选择了操作16\n");
            break;
        case 17:
            printf("你选择了操作17\n");
            break;
        case 18:
            printf("你选择了操作18\n");
            break;
        case 19:
            printf("你选择了操作19\n");
            break;
        case 20:
            printf("你选择了操作20\n");
            break;
        default:
            printf("无效的选择！请输入1到20之间的数字。\n");
            break;
    }

    return 0;
}
