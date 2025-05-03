#include <stdio.h>

int main() {
    int choice;

    // 提示用户输入一个数字
    scanf("%d", &choice);

    double num1, num2;
    
    // 根据用户选择进行相应的操作
    switch (choice) {
        case 1:
            printf("请输入两个数字进行加法：\n");
            printf("第一个数字: ");
            scanf("%lf", &num1);
            printf("第二个数字: ");
            scanf("%lf", &num2);
            printf("结果: %.2lf\n", num1 + num2);
            break;

        case 2:
            printf("请输入两个数字进行减法：\n");
            printf("第一个数字: ");
            scanf("%lf", &num1);
            printf("第二个数字: ");
            scanf("%lf", &num2);
            printf("结果: %.2lf\n", num1 - num2);
            break;

        case 3:
            printf("请输入两个数字进行乘法：\n");
            printf("第一个数字: ");
            scanf("%lf", &num1);
            printf("第二个数字: ");
            scanf("%lf", &num2);
            printf("结果: %.2lf\n", num1 * num2);
            break;

        case 4:
            printf("请输入两个数字进行除法：\n");
            printf("第一个数字: ");
            scanf("%lf", &num1);
            printf("第二个数字: ");
            scanf("%lf", &num2);
            if (num2 != 0) {
                printf("结果: %.2lf\n", num1 / num2);
            } else {
                printf("错误：除数不能为零！\n");
            }
            break;

        case 5:
            printf("请输入两个数字进行求余数：\n");
            printf("第一个数字: ");
            scanf("%lf", &num1);
            printf("第二个数字: ");
            scanf("%lf", &num2);
            if (num2 != 0) {
                printf("结果: %.0lf\n", num1 - (int)(num1 / num2) * num2);
            } else {
                printf("错误：除数不能为零！\n");
            }
            break;

        case 6:
            printf("程序退出。\n");
            break;

        default:
            printf("无效的选择，请选择 1 到 6 之间的数字。\n");
    }

    return 0;
}
