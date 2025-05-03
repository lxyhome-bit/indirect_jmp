/*
   ClassDescriptor: A framework to describe classes
   Copyright (C) 2025 by [Your Name], Example University
*/

#ifndef CLASS_DESCRIPTOR_H
#define CLASS_DESCRIPTOR_H
#include "state.h"
#include "common.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace SBA {
   // 类型定义
   using ADDR = uint64_t; // 内存地址类型

   // 前向声明
   class Program;
   class SCC;
   class Block;
   class Insn;

   //类描述符
    // 一个类可以被一个函数多次实例化，也可以被别的函数多次
   class ClassDescriptor  {
    private:
        Function* parent;   //实例化对象的函数    
        std::vector<std::string> constructors_;    // 构造函数签名
        std::unordered_map<std::string, ADDR> vtable_; // 虚表：函数名到地址的映射
        std::vector<std::string> virtual_functions_;   // 虚函数列表

    public:
      // 构造函数
      ClassDescriptor(const std::string& class_name, ClassDescriptor* parent = nullptr)
         : DescriptorBase(class_name), parent_(parent) {
         if (parent_) {
            parent_->add_child(this); // 自动建立双向继承关系
         }
      }

      // 实现纯虚函数
      std::string get_type() const override { return "Class"; }

      // 重载虚函数
      void print_info() const override {
         DescriptorBase::print_info();
         std::cout << "Parent: " << (parent_ ? parent_->name() : "None") << std::endl;
         std::cout << "Constructors: " << constructors_.size() << std::endl;
         std::cout << "Virtual Functions: " << virtual_functions_.size() << std::endl;
         std::cout << "VTable Entries: " << vtable_.size() << std::endl;
      }

      // 类描述功能
      void add_constructor(const std::string& signature) {
         constructors_.push_back(signature);
      }

      void add_virtual_function(const std::string& name, ADDR address = 0) {
         virtual_functions_.push_back(name);
         if (address) {
            vtable_[name] = address; // 如果提供了地址，则添加到虚表
         }
      }

      void add_child(ClassDescriptor* child) {
         children_.push_back(child);
      }

      // 访问器
      const ClassDescriptor* parent() const { return parent_; }
      const std::vector<ClassDescriptor*>& children() const { return children_; }
      const std::vector<std::string>& constructors() const { return constructors_; }
      const std::vector<std::string>& virtual_functions() const { return virtual_functions_; }
      const std::unordered_map<std::string, ADDR>& vtable() const { return vtable_; }

      // 查询功能
      bool has_virtual_function(const std::string& name) const {
         return std::find(virtual_functions_.begin(), virtual_functions_.end(), name) 
                != virtual_functions_.end();
      }
   };

   // 派生类：接口描述符（示例扩展）
   class InterfaceDescriptor : public DescriptorBase {
    private:
      std::vector<std::string> pure_virtual_functions_; // 纯虚函数列表

    public:
      InterfaceDescriptor(const std::string& interface_name)
         : DescriptorBase(interface_name) {}

      std::string get_type() const override { return "Interface"; }

      void print_info() const override {
         DescriptorBase::print_info();
         std::cout << "Pure Virtual Functions: " << pure_virtual_functions_.size() << std::endl;
      }

      void add_pure_virtual_function(const std::string& name) {
         pure_virtual_functions_.push_back(name);
      }

      const std::vector<std::string>& pure_virtual_functions() const {
         return pure_virtual_functions_;
      }
   };
}

#endif