#include <iostream>
using namespace std;
// 基类 Base
class Base {
public:
    // 虚函数，确保生成虚表
    virtual void show() {
        std::cout << "Base class show function" << std::endl;
    }

    // 另一个虚函数
    virtual void print() {
        std::cout << "Base class print function" << std::endl;
    }

    // 虚析构函数，确保派生类析构时正确调用
    virtual ~Base() {
        std::cout << "Base destructor" << std::endl;
    }
};

// 派生类 Derived
class Derived: public Base   {
public:
    // 重写基类的虚函数 show
    void show() override {
        std::cout << "Derived class show function" << std::endl;
    }

    // 不重写 print 函数，保持基类的实现

    // 派生类的析构函数
    ~Derived() override {
        std::cout << "Derived destructor" << std::endl;
    }
};

int main() {
    // 通过基类指针指向派生类对象，触发多态性
    Derived* ptr = new Derived();
    Derived* ptr2 = new Derived();
    Base* ptr1 = new Base();

    // 调用虚函数，运行时通过虚表解析
    ptr->show();
    ptr->print();

    ptr1->show();
    ptr1->print();

    ptr2->show();
    ptr2->print();
    // 删除对象，触发虚析构函数
    delete ptr;

    return 0;
}
