/*
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab, Stony Brook
   University, Stony Brook, NY 11794.                                         
                                                                              
   Scalable, Sound, and Accurate Jump Table Analysis (ISSTA 2024)             
*/

#include <iostream>
#include <nlohmann/json.hpp>

#include "../../include/sba/common.h"
#include "../../include/sba/state.h"
#include "../../include/sba/domain.h"
#include "../../include/sba/framework.h"
#include "../../include/sba/program.h"
#include "../../include/sba/function.h"
#include "../../include/sba/scc.h"
#include "../../include/sba/block.h"
#include "../../include/sba/insn.h"
#include "../../include/sba/rtl.h"
#include "../../include/sba/expr.h"

using namespace std;
using namespace SBA;

#define RECUR_LIMIT 200
/* -------------------------------------------------------------------------- */
function<void(const UnitId&, AbsVal&)> init = [](const UnitId& id, AbsVal& out)
-> void {
   /* BaseLH */
   ABSVAL(BaseLH,out) = !bounded(id.r(),id.i())? BaseLH(BaseLH::T::TOP):
                                                 BaseLH(get_sym(id));
   /* BaseStride */
   if (id.r()==REGION::REGISTER && SYSTEM::call_args.contains((SYSTEM::Reg)(id.i())))
      ABSVAL(BaseStride,out) = BaseStride(BaseStride::T::DYNAMIC);
   else
      ABSVAL(BaseStride,out) = BaseStride(BaseStride::T::TOP);

   /* Taint */
   if (SYSTEM::call_args.contains((SYSTEM::Reg)(id.i())))
      ABSVAL(Taint,out) = Taint(0x0);
   else
      ABSVAL(Taint,out) = Taint(0xffffffff);
};


State::StateConfig config{true, true, false, 1, &init};
unordered_set<IMM> skipped;
string d_base, f_out, f_auto, f_obj;


void help() {
   cout << "Usage:  jump_table [-d <dir_base>] [-o <file_out>]"
                          << " <file_auto> <file_object>" << endl;
   exit(1);
}

// Usage:  jump_table [-d <dir_base>] [-o <file_out>] <file_auto> <file_object>
void setup(int argc, char **argv) {
   // fobj是输入的二进制文件
   f_obj = std::string(argv[argc-1]);
   f_auto = std::string(argv[argc-2]);
   if (!std::filesystem::exists(f_auto) || !std::filesystem::exists(f_obj))
      help();
   
   d_base = "/home/llh/sba/";
   f_out = d_base + "result.json";

// 如果参数不规范，则调用help
   if (argc < 3 || argc > 7)
      help();
// 将参数中的-o -d 后面的提取出来
   for (int i = 0; i < ((argc-3) >> 1); ++i) {
      auto s1 = std::string(argv[2*i+1]);
      auto s2 = std::string(argv[2*i+2]);
      if (s1.compare("-d") == 0)
         d_base = s2;
      else if (s1.compare("-o") == 0)
         f_out = s2;
   }

   Framework::setup(d_base, f_auto);
}


bool should_analyze(Program* p, Function* f) {
   /* found 1 unexplored jump --> analyze */
   if (!skipped.contains(f->offset())) {
      for (auto scc: f->scc_list())
      for (auto b: scc->block_list())
      for (auto i: b->insn_list())
         if (i->indirect()) {
            auto it = p->icfs().find(i->offset());
            if (it == p->icfs().end() || it->second.empty())
               return true;
         }
   }
   /* explored all jumps --> not analyze, mark skip */
   skipped.insert(f->offset());
   return false;
}



// 方便使用
using json = nlohmann::json;

std::string to_hex(int val) {
   std::stringstream ss;
   ss << std::hex << val;
   return ss.str();
}

void generate_json_output(const std::string& f_out, /* 你的 p 对象类型 */Program* p) {
    // 创建 JSON 对象
    json output;

    // 间接跳转位置部分
    json icf_data = json::object();
    for (const auto& [jump_loc, targets] : p->icfs()) {
        json target_array = json::array();
        for (const auto& t : targets) {
            target_array.push_back(to_hex(t));
        }
        icf_data[(to_hex(jump_loc))] = target_array;
    }
    output["indirect_jump_locations"] = icf_data;

    // 跳转表位置部分
    json jtable_data = json::object();
    for (const auto& [jtable, targets] : p->jtable_targets) {
        json target_array = json::array();
            for (const auto& t : targets) {
            target_array.push_back(to_hex(t));
        }
        jtable_data[(to_hex(jtable))] = target_array;
    }
    output["jump_table_locations"] = jtable_data;


   //  虚函数位置部分
   json vfunc_data = json::object();
   for (const auto& [vaddr, targets] : p->vfunc) {
      vfunc_data[(to_hex(vaddr))] = to_hex(targets);
   }
   output["vfunc_locations"] = vfunc_data;
      
    // 写入文件
    std::ofstream f1(f_out);
    f1 << output.dump(4); // 4 个空格缩进，便于阅读
    f1.close();
}

int main(int argc, char **argv) {
   setup(argc, argv);

   auto p = Framework::create_program(f_obj, {}, {});
   if (p == nullptr) {
      cout << "Errors occurred while analyzing " << f_obj << endl;
      exit(1);
   }
   LOG_START("/home/llh/sba/log.txt");
   /* start with definite fptrs */
   auto def_fptrs = p->definite_fptrs();
   vector<IMM> fptrs(def_fptrs.begin(), def_fptrs.end());
   for (auto x: p->prolog_fptrs())
      if (!def_fptrs.contains(x))
         fptrs.push_back(x);

   while (!fptrs.empty() && p->update_num <= RECUR_LIMIT) {
      p->fptrs(fptrs);
      p->update();

      /* reduce gaps by resolving targets of indirect jumps */
      while (true) {
         auto prev_cnt = p->icfs().size();
         for (auto fptr: p->fptrs()) {
            // 创建字符串流
            std::stringstream stream;
            // 将十进制变量转换为十六进制并存储到字符串流中
            stream << std::hex << fptr;
            // 获取十六进制字符串
            std::string hexString = stream.str();
            if (fptr == 5242){
               hexString = stream.str();
            }
            if (p->updated(fptr)) {
               auto f = p->func(fptr);
               if (f != nullptr) {
                  if (should_analyze(p, f)) {
                     f->analyze(config);
                     f->resolve_icf();
                  }
                  delete f;
               }
            }
         }
         p->resolve_unbounded_icf();
         if (prev_cnt == p->icfs().size())
            break;
         p->update();
      }

      /* scan gaps for more fptrs */
      fptrs = p->scan_fptrs_in_gap();
   }
   LOG_STOP();

   // 处理虚函数
   for (auto fptr: p->fptrs()) {
      auto f = p->func(fptr);
      f->analyze(config);
   }

   /* results */
   fstream f1(f_out, fstream::out);
   f1 << "Indirect Jump Location --> List of Targets\n";
   for (auto const& [jump_loc, targets]: p->icfs()) {
      f1 << jump_loc << " ";
      for (auto t: targets)
         f1 << t << " ";
      f1 << "\n";
   }
   f1 << "\n\n";
   f1 << "Jump Table Location --> List of Targets\n";
   for (auto const& [jtable, targets]: p->jtable_targets) {
      f1 << jtable << " ";
      for (auto t: targets)
         f1 << t << " ";
      f1 << "\n";
   }
   f1.close();

   generate_json_output(f_out,p);

   Framework::clean();

   return 0;
}
