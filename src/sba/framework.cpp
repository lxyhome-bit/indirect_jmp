/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "../../include/sba/framework.h"
#include "../../include/sba/program.h"
#include "../../include/sba/rtl.h"
#include "../../include/sba/parser.h"
#include <cstring>
#include <unistd.h>
#include <caml/alloc.h>
#include <caml/mlvalues.h>
#include <caml/callback.h>
#include <iostream>
#include <cstdlib>      // 用于 std::system
#include <fstream>      // 用于文件读写
#include <string>       // 用于 std::string
#include <filesystem>   // 用于文件系统操作 (C++17)
#include <map>

using namespace SBA;


int Framework::session;
string Framework::d_base;
string Framework::d_session;

// 启动规则学习，输入auto给ocaml
static void ocaml_load(const string& f_auto) {
   static const value * closure_f = nullptr;
   if (closure_f == nullptr)
      closure_f = caml_named_value("Load callback");
   auto s = f_auto.c_str();
   caml_callback(*closure_f, caml_alloc_initialized_string(strlen(s), s));
}


static void ocaml_lift(const string& f_asm, const string& f_rtl) {
   static const value* closure_f = nullptr;
   if (closure_f == nullptr)
      closure_f = caml_named_value("Lift callback");
   auto s1 = f_asm.c_str();
   auto s2 = f_rtl.c_str();
   caml_callback2(*closure_f, caml_alloc_initialized_string(strlen(s1), s1),
                              caml_alloc_initialized_string(strlen(s2), s2));

   // 指定绝对路径
   std::string asm_output_path = "/home/llh/sba/f_asm.txt";
   std::string rtl_output_path = "/home/llh/sba/f_rtl.txt";

   // // 确保目录存在
   // std::filesystem::create_directories("/home/user/output/");

// 读取 f_asm 文件并写入 asm_output_path
    std::ifstream asm_input_file(f_asm);  // 输入文件流
    std::ofstream asm_output_file(asm_output_path);  // 输出文件流
    if (asm_input_file.is_open() && asm_output_file.is_open()) {
        std::string line;
        while (std::getline(asm_input_file, line)) {
            asm_output_file << line << "\n";  // 逐行读取并写入
        }
        asm_input_file.close();
        asm_output_file.close();
    } else {
        std::cerr << "无法打开文件: " << (asm_input_file.is_open() ? asm_output_path : f_asm) << std::endl;
    }

    // 读取 f_rtl 文件并写入 rtl_output_path
    std::ifstream rtl_input_file(f_rtl);
    std::ofstream rtl_output_file(rtl_output_path);
    if (rtl_input_file.is_open() && rtl_output_file.is_open()) {
        std::string line;
        while (std::getline(rtl_input_file, line)) {
            rtl_output_file << line << "\n";  // 逐行读取并写入
        }
        rtl_input_file.close();
        rtl_output_file.close();
    } else {
        std::cerr << "无法打开文件: " << (rtl_input_file.is_open() ? rtl_output_path : f_rtl) << std::endl;
    }
}



static vector<tuple<IMM,RTL*,vector<uint8_t>>> load(const string& f_asm,
const string& f_rtl, const string& f_raw, const unordered_set<IMM>&
noreturn_calls = {}) {
   string itc, rtl, raw;
   vector<tuple<IMM,RTL*,vector<uint8_t>>> res;
   string one_byte;
   vector<uint8_t> raw_bytes;

   fstream f1(f_asm, fstream::in);
   fstream f2(f_rtl, fstream::in);
   fstream f3(f_raw, fstream::in);

   while (getline(f1,itc) && getline(f2,rtl) && getline(f3,raw)) {
      RTL* object = nullptr;
      IMM offset = Util::to_int(itc.substr(2, itc.find(" ")-2));
      auto it = noreturn_calls.find(offset);
      if (it == noreturn_calls.end()) {
         object = Parser::process(rtl);
         raw_bytes.clear();
         for (IMM i = 0; i < (IMM)(raw.length()); i += 3)
            raw_bytes.push_back((uint8_t)Util::to_int("0x" + raw.substr(i,2)));
      }
      else {
         object = new Exit(Exit::EXIT_TYPE::HALT);
         raw_bytes = SYSTEM::HLT_BYTES;
         LOG2("fix: instruction " << offset << " is a non-returning call");
      }

      res.push_back({offset, object, raw_bytes});
      if (object == nullptr) {
         LOG2("error: failed to lift at " << offset << ": "
            << itc.substr(itc.find(" ")+1, string::npos));
         #if ABORT_UNLIFTED_INSN == true
            for (auto [offset, object, raw_bytes]: res)
               delete object;
            break;
         #endif
      }
   }
   f1.close();
   f2.close();
   f3.close();

   return res;
}


Program* Framework::create_program(const string& f_obj, const vector<IMM>&
fptrs, const unordered_map<IMM,unordered_set<IMM>>& indirect_targets) {
   auto f_asm = Framework::d_session + "asm";
   auto f_rtl = Framework::d_session + "rtl";
   auto f_raw = Framework::d_session + "raw";
   // 反汇编data段，并且写入adm和raw文件里面
   SYSTEM::disassemble(f_obj, f_asm, f_raw);
   ocaml_lift(f_asm, f_rtl);
   // 得到所有的虚函数表地址
   std::tuple<bool,IMM,unordered_map<IMM, unordered_set<IMM>>> v_tables_pair = ELF_x86::vtables_by_rel(f_obj);
   unordered_map<IMM, unordered_set<IMM>> v_tables = std::get<2>(v_tables_pair);
   bool striped = std::get<0>(v_tables_pair);
   IMM file_offset = std::get<1>(v_tables_pair);

   // 得到构造函数和虚表
   auto noreturn_calls = SYSTEM::noreturn_calls(f_obj);
   auto offset_rtl_raw = load(f_asm, f_rtl, f_raw, noreturn_calls);
   auto p = new Program(f_obj, offset_rtl_raw, fptrs, indirect_targets);
   p->striped = striped;
   unordered_map<IMM,IMM> constructors = p->find_vtable_constructors();
   std::pair<std::unordered_set<IMM>,std::unordered_map<IMM, IMM>> vfunc = p->scan_vfunc(constructors,v_tables,f_obj,file_offset);
   p->vfunc = vfunc.second;
   
   if (!p->faulty)
      return p;
   else {            
      delete p;
      return nullptr;
   }
}

// 创建工作目录，初始化caml环境，将数据集传给ocaml
void Framework::setup(const string& d_base, const string& f_auto) {
   /* filename */
   Framework::session = getpid();
   Framework::d_base = d_base;
   Framework::d_session = d_base + std::to_string(Framework::session) + "/";
   std::filesystem::create_directories(Framework::d_session);

   /* lifter */
   char** argv = (char**)malloc(5*sizeof(char*));
   char t0[] = "interface";
   char t1[] = "-c";
   char t2[] = "on";
   char t3[] = "-p";
   argv[0] = t0;
   argv[1] = t1;
   argv[2] = t2;
   argv[3] = t3;
   argv[4] = nullptr;
   caml_startup(argv);
   ocaml_load(f_auto);
}


void Framework::clean() {
   std::filesystem::remove_all(d_session);
}
