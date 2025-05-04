/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "../../include/sba/program.h"
#include "../../include/sba/framework.h"
#include "../../include/sba/function.h"
#include "../../include/sba/block.h"
#include "../../include/sba/insn.h"
#include "../../include/sba/rtl.h"
#include "../../include/sba/expr.h"
#include "../../include/sba/domain.h"

using namespace SBA;
/* -------------------------------- Program --------------------------------- */
Program::Program(const string& f_obj, const
vector<tuple<IMM,RTL*,vector<uint8_t>>>& offset_rtl_raw, const
vector<IMM>& fptr_list, const unordered_map<IMM,unordered_set<IMM>>& indirect_targets):
faulty(false),
#if ENABLE_DETECT_UPDATED_FUNCTION
   update_num(0),
#endif
icfs_(indirect_targets), f_obj_(f_obj) {

   SYSTEM::load(info_, f_obj_);
   info_.insns = &i_map_;

   sorted_insns_.reserve(offset_rtl_raw.size());
   for (auto [offset, rtl, raw]: offset_rtl_raw) {
      auto insn = new Insn(offset, rtl, raw);
      i_map_[offset] = insn;
      sorted_insns_.push_back(insn);
   }

   for (auto [jump_loc, expr]: indirect_targets)
      if (i_map_.contains(jump_loc))
         recent_icfs_.push_back(jump_loc);

   fptrs(fptr_list);
   if (!fptr_list.empty())
      update();
}


Program::~Program() {
   for (auto [offset, b]: b_map_)
      delete b;
   for (auto [offset, i]: i_map_)
      delete i;
}


void Program::build_func(IMM entry, const unordered_map<IMM,unordered_set<IMM>>& icfs,
const vector<IMM>& norets) {
   for (auto [offset, b]: b_map_)
      delete b;
   b_map_.clear();
   recent_fptrs_ = vector<IMM>{entry};
   icfs_ = icfs;
   recent_norets_ = unordered_set<IMM>(norets.begin(), norets.end());
   update();
}
/* -------------------------------------------------------------------------- */
void Program::block_split(Insn* insn) {
   /* [           insn      ] */
   /* [         ][          ] */
   /*      b        b_next    */
   auto b = insn->parent;
   auto it = std::find(b->insn_list().begin(), b->insn_list().end(), insn);
   auto b_next = new Block(vector<Insn*>(it, b->insn_list().end()));
   for (auto const& [v, c]: b->succ())
      b_next->succ(v, c);
   b_map_[b_next->offset()] = b_next;
   b->shrink_insn_list(it);
   b->shrink_succ();
   b->succ(b_next, COMPARE::NONE);
}


void Program::block_connect(Block* b, IMM target, COMPARE cond, bool fix_prefix) {
   auto it = i_map_.find(target);
   if (it != i_map_.end()) {
      /* non-existed target, connect now */
      if (it->second->parent == nullptr) {
         block_dfs(it->second);
         b->succ(it->second->parent, cond);
      }
      /* existed target, connect now */
      else if (it->second == it->second->parent->first())
         b->succ(it->second->parent, cond);
      /* split target, connect later */
      else
         split_.push_back({b->last(), it->second, cond});
   }
   else if (fix_prefix && ENABLE_COMPATIBLE_INPUT) {
      LOG2("fix: suppose " << target << " is a lock-prefix instruction");
      block_connect(b, target-1, cond);
   }
   else
      b->faulty = true;
}


void Program::block_dfs(Insn* i) {
   vector<Insn*> i_list{i};
   while (true) {
      /* A. transfer */
      if (i->transfer()) {
         auto b_curr = new Block(i_list);
         b_map_[b_curr->offset()] = b_curr;
         i_list.clear();

         /* direct targets */
         Array<uint8_t,pair<IMM,COMPARE>,2> cft;
         if (i->direct()) {
            /* direct jump */
            if (!i->call()) {
               auto target = i->direct_target().first;
               auto cond = i->cond_op().first;
               block_connect(b_curr, target, cond, true);
               if (b_curr->faulty) {
                  LOG4("error: missing direct target " << target);
                  #if ABORT_MISSING_DIRECT_TARGET
                     faulty = true;
                     return;
                  #endif
               }
            }
            /* fall-through */
            if ((i->call() && !recent_norets_.contains(i->offset())) || i->cond_jump()) {
               auto target = i->direct_target().second;
               auto cond = i->cond_op().second;
               block_connect(b_curr, target, cond);
               if (b_curr->faulty) {
                  LOG4("error: missing fall-through target " << target);
                  #if ABORT_MISSING_FALLTHROUGH_TARGET
                     faulty = true;
                     return;
                  #elif ENABLE_COMPATIBLE_INPUT
                     if (i->call()) {
                        i->replace(new Exit(Exit::EXIT_TYPE::HALT), SYSTEM::HLT_BYTES);
                        LOG2("fix: mark " << i->offset() << " as a halt instruction");
                        b_curr->faulty = false;
                        b_curr->shrink_succ();
                     }
                  #endif
               }
            }
         }
         else {
            if (i->call()) {
               auto target = i->direct_target().first;
               auto cond = i->cond_op().first;
               block_connect(b_curr, target, cond);
               if (b_curr->faulty) {
                  LOG4("error: missing fall-through target " << target);
                  #if ABORT_MISSING_FALLTHROUGH_TARGET
                     faulty = true;
                     return;
                  #endif
               }
            }
         }

         /* indirect targets */
         if (i->indirect() && i->jump()) {
            auto it = icfs_.find(i->offset());
            if (it != icfs_.end()) {
               for (auto t: it->second) {
                  block_connect(b_curr, t, COMPARE::NONE);
                  if (b_curr->faulty) {
                     LOG4("error: missing indirect target " << t);
                     #if ABORT_MISSING_FALLTHROUGH_TARGET
                        faulty = true;
                        return;
                     #endif
                  }
               }
            }
         }

         return;
      }

      /* B. exit */
      else if (i->halt()) {
         auto b_curr = new Block(i_list);
         b_map_[b_curr->offset()] = b_curr;
         i_list.clear();
         return;
      }

      /* C. non-control */
      else {
         auto it = i_map_.find(i->next_offset());
         if (it != i_map_.end()) {
            auto next = it->second;
            if (next->parent != nullptr) {
               auto b_curr = new Block(i_list);
               b_map_[b_curr->offset()] = b_curr;
               i_list.clear();
               b_curr->succ(next->parent, COMPARE::NONE);
               return;
            }
            else {
               i_list.push_back(next);
               i = next;
            }
         }
         else {
            #if ABORT_MISSING_NEXT_INSN
               faulty = true;
               LOG4("error: missing next instruction for " << i->offset());
            #else
               auto b_curr = new Block(i_list);
               b_map_[b_curr->offset()] = b_curr;
               #if ENABLE_COMPATIBLE_INPUT
                  auto object = new Exit(Exit::EXIT_TYPE::HALT);
                  i->replace(object, SYSTEM::HLT_BYTES);
                  LOG2("fix: mark " << i->offset() << " as a halt instruction");
                  b_curr->shrink_succ();
               #else
                  b_curr->faulty = true;
                  LOG4("error: missing next instruction at " << i->offset());
               #endif
            #endif
            return;
         }
      }
   }
}
/* -------------------------------------------------------------------------- */
Function* Program::func(IMM fptr) {
   checked_fptrs_.insert(fptr);
   auto f = new Function(this, b_map_[fptr]);
   if (f->faulty) {
      LOG2("function " << fptr << " is faulty!");
      delete f;
      return nullptr;
   }
   return f;
}


void Program::fptrs(const vector<IMM>& fptr_list) {
   recent_fptrs_ = fptr_list;
   fptrs_.insert(fptr_list.begin(), fptr_list.end());
   #if ENABLE_SUPPORT_CONSTRAINT
   sorted_fptrs = vector<IMM>(fptrs_.begin(), fptrs_.end());
   std::sort(sorted_fptrs.begin(), sorted_fptrs.end());
   #endif
}


#if ENABLE_DETECT_UPDATED_FUNCTION
void Program::propagate_update(Block* b) {
   b->update_num = update_num;
   for (auto p: b->superset_preds)
      if (p->update_num < update_num)
         propagate_update(p);
}
#endif


bool Program::updated(IMM fptr) {
   #if ENABLE_DETECT_UPDATED_FUNCTION
   auto it = b_map_.find(fptr);
   return (it != b_map_.end() && it->second->update_num == update_num);
   #else
   return true;
   #endif
}

void Program::resolve_vfunc(const string& f_obj){
   // 得到所有的虚函数表地址
   std::tuple<bool,IMM,unordered_map<IMM, unordered_set<IMM>>> v_tables_pair = ELF_x86::vtables_by_rel(f_obj);
   unordered_map<IMM, unordered_set<IMM>> v_tables = std::get<2>(v_tables_pair);
   bool striped = std::get<0>(v_tables_pair);
   IMM file_offset = std::get<1>(v_tables_pair);
   striped = striped;
   // unordered_map<IMM,IMM> constructors = find_vtable_constructors();
   std::pair<std::unordered_set<IMM>,std::unordered_map<IMM, IMM>> vfunc = scan_vfunc(vtables,v_tables,f_obj,file_offset);
   this->vfunc = vfunc.second;
}


void Program::update() {
   /* update existing blocks with recent_icfs_ */
   for (auto jump_loc: recent_icfs_) {
      auto it = i_map_.find(jump_loc);
      if (it != i_map_.end() && it->second->parent != nullptr) {
         auto b = it->second->parent;
         for (auto t: icfs_.at(jump_loc)) {
            block_connect(b, t, COMPARE::NONE);
            if (b->faulty) {
               LOG4("error: missing indirect target " << t);
               #if ABORT_MISSING_INDIRECT_TARGET
               faulty = true;
               return;
               #endif
            }
         }
      }
   }

   /* blocks reached from recent_fptrs_ */
   for (auto offset: recent_fptrs_) {
      auto it = i_map_.find(offset);
      if (it != i_map_.end()) {
         if (!b_map_.contains(offset))
            block_dfs(it->second);
      }
      #if ABORT_MISSING_FUNCTION_ENTRY
      else {
         LOG4("error: missing function entry " << t);
         faulty = true;
         return;
      }
      #endif
   }

   /* split blocks */
   for (auto [transfer, target, cond]: split_)
      if (target != target->parent->first()) {
         #if DLEVEL >= 4
         auto b1 = target->parent;
         string s = string("split basic block [")
                  + std::to_string(b1->first()->offset()) + string(" .. ")
                  + std::to_string(b1->last()->offset()) + string("]");
         #endif
         block_split(target);
         #if DLEVEL >= 4
         auto b2 = target->parent;
         s += string(" into [")
            + std::to_string(b1->first()->offset()) + string(" .. ")
            + std::to_string(b1->last()->offset()) + string("] and [")
            + std::to_string(b2->first()->offset()) + string(" .. ")
            + std::to_string(b2->last()->offset()) + string("]");
         LOG4(s);
         #endif
         transfer->parent->succ(target->parent, cond);
      }
   split_.clear();

   /* detect updated functions */
   #if ENABLE_DETECT_UPDATED_FUNCTION
   ++update_num;
   for (auto jump_loc: recent_icfs_) {
      auto it = i_map_.find(jump_loc);
      if (it != i_map_.end() && it->second->parent != nullptr)
         propagate_update(it->second->parent);
   }
   for (auto jump_loc: recent_fptrs_) {
      auto it = i_map_.find(jump_loc);
      if (it != i_map_.end() && it->second->parent != nullptr) {
         it->second->parent->update_num = update_num;
         it->second->parent->superset_preds.clear();
      }
   }
   #endif
   recent_icfs_.clear();
   recent_fptrs_.clear();
}
/* -------------------------------------------------------------------------- */
void Program::icf(IMM jump_loc, const unordered_set<IMM>& targets) {
   if (targets.empty()) {
      icfs_[jump_loc] = {};
      return;
   }
   auto& ref = icfs_[jump_loc];
   auto old_size = ref.size();
   ref.insert(targets.begin(), targets.end());
   if (old_size < ref.size())
      recent_icfs_.push_back(jump_loc);
}


#if ENABLE_RESOLVE_ICF
bool Program::valid_icf(IMM target, Function* func) const {
   if (valid_icf(target)) {
      for (auto [l,r]: func->code_range)
         if (l <= target && target < r)
            return true;
   }
   return false;
}


void Program::resolve_unbounded_icf() {
   for (auto const& [jump_loc, jtables]: unbounded_icf_jtables) {
      unordered_set<IMM> targets;
      /* (1) jtable_targets */
      for (auto jtable: jtables) {
         auto it = jtable_targets.find(jtable);
         if (it != jtable_targets.end())
            targets.insert(it->second.begin(), it->second.end());
      }
      /* (2) unbounded_icf_targets */
      auto it = unbounded_icf_targets.find(jump_loc);
      if (targets.empty() && it != unbounded_icf_targets.end())
         targets = it->second;

      icf(jump_loc, targets);
      LOG2("found " << targets.size() << " indirect targets at " << jump_loc);
      string s = "";
      for (auto t: targets)
         s.append(std::to_string(t)).append(" ");
      LOG3(s);
   }

   unbounded_icf_jtables.clear();
   unbounded_icf_targets.clear();
}


void Program::resolve_icf(
unordered_map<IMM,unordered_set<IMM>>& bounded_targets,
unordered_map<IMM,unordered_set<IMM>>& unbounded_targets,
Function* func, BaseStride* expr, const function<int64_t(int64_t)>& f) {
   for (BaseStride* X = expr; X != nullptr; X = X->next_value())
   if (!X->top() || !X->dynamic()) {
      auto b = (int64_t)X->base();
      auto s = (int64_t)X->stride();
      auto w = X->width();
      auto x = X->index();
      if (s == 0) {
         auto t = (X->nmem())?
                  f(b): f(Util::cast_int(read(b, w), w));
         if (valid_icf(t)) {
            unbounded_targets[-1].insert(t);
            LOG4("#0: " << t);
         }
      }
      else if (x->top() || x->dynamic()) {
         #if ENABLE_SUPPORT_CONSTRAINT
         if (!x->bounds().full() && !x->bounds().empty() &&
         0 < x->bounds().hi() && x->bounds().hi() < LIMIT_JTABLE) {
            for (auto addr = b;
                      addr <= b + x->bounds().hi() * s; addr += s) {
               auto t = (X->nmem())?
                        f(addr): f(Util::cast_int(read(addr, w), w));
               if (valid_icf(t)) {
                  LOG4("#" << (addr-b)/s << ": " << t);
                  bounded_targets[b].insert(t);
               }
            }
         }
         else
         #endif
         {
            for (auto addr = b; addr < b + LIMIT_JTABLE; addr += s) {
               auto t = (X->nmem())?
                        f(addr): f(Util::cast_int(read(addr, w), w));
               if (valid_icf(t)) {
                  LOG4("#" << (addr-b)/s << ": " << t);
                  unbounded_targets[b].insert(t);
               }
               else
                  break;
            }
         }
      }
      else {
         if (X->nmem(), func) {
            resolve_icf(bounded_targets, unbounded_targets, func, x,
            [&](int64_t x_val)->int64_t {
               return f(b + s * x_val);
            });
         }
         else
            resolve_icf(bounded_targets, unbounded_targets, func, x,
            [&](int64_t x_val)->int64_t {
               return f(Util::cast_int(read(b + s*x_val, w), w));
            });
      }
   }
}
#endif
/* -------------------------------------------------------------------------- */
uint64_t Program::read(int64_t offset, uint8_t width) const {
   return SYSTEM::read(info_, offset, width);
}


unordered_set<IMM> Program::definite_fptrs() const {
   return SYSTEM::definite_fptrs(info_, f_obj_);
}


unordered_set<IMM> Program::prolog_fptrs() const {
   unordered_set<IMM> res;
   for (auto it = sorted_insns_.begin(); it != sorted_insns_.end(); ++it) {
      auto it2 = it;
      if (SYSTEM::prolog((*it)->raw_bytes()) >= 2) {
         // 这里的15是保守处理的，以15行指令为单位，查找函数入口
         for (uint8_t i = 0; i < 15; ++i) {
            ++it2;
            if (it2 != sorted_insns_.end()) {
               if (SYSTEM::prolog((*it2)->raw_bytes()) >= 1){
                  res.insert((*it)->offset());
                  // break;
                  }
            }
            else
               break;
         }
      }
      if (it2 == sorted_insns_.end())
         break;
      it = it2;
   }
   return res;
}

// 最后会找到虚构函数和构造函数，不过不影响
unordered_map<IMM,IMM> Program::find_vtable_constructors() const {
   // 构造函数入口 -- 虚表的地址
   unordered_map<IMM,IMM> constructors;
   
   // 遍历所有指令
   for (auto it = sorted_insns_.begin(); it != sorted_insns_.end(); ++it) {
      // 第一步：检测栈帧设置
      uint8_t prolog_score = SYSTEM::prolog((*it)->raw_bytes());
      if (prolog_score != 2) {
         continue;  // 如果不是函数开头就跳过
      }

      auto start_it = it;
      bool has_this_ptr = false;  // 是否找到this指针传递
      bool has_vptr_init = false; // 是否找到虚表指针初始化
      IMM vtable_addr = 0;        // 虚表地址
      
      for (uint8_t i = 0; i < 20 && it != sorted_insns_.end(); ++i, ++it) {
         if(SYSTEM::prolog((*it)->raw_bytes()) == 2 && i != 0)    break;

         
         const vector<uint8_t>& bytes = (*it)->raw_bytes();
         
         // 第二步：检测 this 指针传递
         if (bytes.size() >= 4 && !has_this_ptr) {
             // 检查 mov [rbp-0x8], rdi (48 89 7d f8)
             if (bytes[0] == 0x48 && bytes[1] == 0x89 && bytes[2] == 0x7d && bytes[3] == 0xf8) {
                 has_this_ptr = true;
             }
             // 可选：保留原始检测 mov rcx, rsi (48 89 f1) 或 mov rcx, rdi (48 89 f9)
             else if (bytes.size() >= 3 && 
                      ((bytes[0] == 0x48 && bytes[1] == 0x89 && bytes[2] == 0xf1) ||  // mov rcx, rsi
                       (bytes[0] == 0x48 && bytes[1] == 0x89 && bytes[2] == 0xf9))) {  // mov rcx, rdi
                 has_this_ptr = true;
             }
         }
         
         // 第三步：检测虚表指针初始化
         if (bytes.size() >= 7 && 
             bytes[0] == 0x48 &&    // REX.W 前缀
             bytes[1] == 0x8d &&    // LEA 操作码
            //RIP 相对寻址的 ModR/M 字节  
            //  bytes[2] == 0x15       //,这是rdx的
            bytes[2] == 0x0d     //这是rcx的
            ) {   
             has_vptr_init = true;
     
             // 计算虚表地址：RIP + 偏移量
             IMM rip = (*it)->offset() + bytes.size();
             int32_t offset = (bytes[6] << 24) | (bytes[5] << 16) | 
                             (bytes[4] << 8) | bytes[3];
             vtable_addr = rip + offset;
         }
     }
      
      // 如果三个条件都满足，则记录构造函数位置
      IMM address = (*start_it)->offset();
      if (prolog_score >= 1 && has_this_ptr && has_vptr_init) {
         constructors.insert({address,vtable_addr});
      }
      
      it = start_it;  // 重置迭代器以检查重叠序列
   }

   return constructors;
}

/*
v_tables中存储了所有的可能的虚函数地址（可能含有多余的地址），
然后根据一张虚表中的虚函数地址是连续的，即他们之间的地址都相差8字节，
vtable_dst里面存储的事所有的虚表表头，所以就可以从表头开始不断以8字节为单位查看对应的地址是否在v_tables中，
每当失败的时候，就说明一张虚表已经结束
*/

// 返回2个东西，一个是所有的虚表表头，一个是所有的虚表地址与实际地址的映射
std::pair<std::unordered_set<IMM>,std::unordered_map<IMM, IMM>> Program::scan_vfunc(
   std::unordered_set<IMM> constructors,
   std::unordered_map<IMM, std::unordered_set<IMM>> v_tables,
   const string& file,
   IMM file_offset
   ) {
   
   // 提取所有的虚表表头地址
   std::unordered_set<IMM> vtable_dst;
   for (const auto& pair : constructors) {
       IMM vtable_addr = pair;  // 构造函数对应的虚表地址
       vtable_dst.insert(vtable_addr);
   }
   
   // 存储识别到的虚表表头
   std::unordered_set<IMM> vtb_h;
   std::unordered_map<IMM, IMM> addr_pair;
   
   std::unordered_set<IMM> vfunc_set;

   // 遍历每个虚表表头
   for (const IMM& vtable_addr : vtable_dst) {
      IMM current_addr = vtable_addr;  // 从表头开始
      bool valid = false;
      while (true) {
         // 检查 current_addr 是否在 v_tables 的任意值集合中
         bool found = false;
         for (const auto& pair : v_tables) {
            const std::unordered_set<IMM>& table_entries = pair.second;
            if (table_entries.find(current_addr) != table_entries.end()) {
                  found = true;
                  valid = true;
                  vfunc_set.insert(current_addr);  // 将表项地址加入 vfunc_set
                  break;  // 找到后无需继续检查其他集合
            }
         }
         
         if (found) {
            current_addr += 8;  // 移动到下一个地址（+8字节）
         } else {
            break;  // 地址不在任何值集合中，虚表结束
         }
      }
      if(valid){
         vtb_h.insert(vtable_addr);
      }
   }

   std::ifstream elf_file(file, std::ios::binary);

   for (const auto& addr : vfunc_set){
      
      elf_file.seekg(addr-file_offset, std::ios::beg);
      IMM new_address = 0;
      elf_file.read(reinterpret_cast<char*>(&new_address), sizeof(IMM));
      addr_pair[addr] = new_address;
   }
   std::pair<std::unordered_set<IMM>,std::unordered_map<IMM, IMM>> result(vtb_h,addr_pair);

   return result;
}


std::pair<uint64_t, uint64_t> SBA::Program::get_text_section_range(const std::string& filename) {
   int fd = open(filename.c_str(), O_RDONLY);
   if (fd < 0) {
       throw std::runtime_error("无法打开 ELF 文件: " + filename);
   }

   Elf64_Ehdr ehdr;
   if (::read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
       close(fd);
       throw std::runtime_error("无法读取 ELF 文件头");
   }

   if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
       close(fd);
       throw std::runtime_error("不是 ELF 文件");
   }

   if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
       close(fd);
       throw std::runtime_error("仅支持 64 位 ELF 文件");
   }

   std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
   if (lseek(fd, ehdr.e_shoff, SEEK_SET) == -1 ||
       ::read(fd, shdrs.data(), ehdr.e_shnum * sizeof(Elf64_Shdr)) !=
           ehdr.e_shnum * sizeof(Elf64_Shdr)) {
       close(fd);
       throw std::runtime_error("无法读取节头表");
   }

   if (ehdr.e_shstrndx >= ehdr.e_shnum) {
       close(fd);
       throw std::runtime_error("无效的字符串表索引");
   }
   Elf64_Shdr strtab_shdr = shdrs[ehdr.e_shstrndx];
   std::vector<char> strtab(strtab_shdr.sh_size);
   if (lseek(fd, strtab_shdr.sh_offset, SEEK_SET) == -1 ||
       ::read(fd, strtab.data(), strtab_shdr.sh_size) != strtab_shdr.sh_size) {
       close(fd);
       throw std::runtime_error("无法读取字符串表");
   }

   for (size_t i = 0; i < ehdr.e_shnum; ++i) {
       const char* section_name = strtab.data() + shdrs[i].sh_name;
       if (std::strcmp(section_name, ".text") == 0) {
           uint64_t start = shdrs[i].sh_addr;
           uint64_t size = shdrs[i].sh_size;
           close(fd);
           return {start, start + size};
       }
   }

   close(fd);
   throw std::runtime_error("未找到 .text 节");
}


unordered_set<IMM> Program::scan_cptrs() const {
   /* stored cptrs */
   auto res = SYSTEM::stored_cptrs(info_, 8);
   auto cptrs4 = SYSTEM::stored_cptrs(info_, 4);
   res.insert(cptrs4.begin(), cptrs4.end());

   /* pc-relative encoding */
   auto pc_rel = new Binary(Binary::OP::PLUS, Expr::EXPR_MODE::DI,
                 new Reg(Expr::EXPR_MODE::DI, SYSTEM::INSN_PTR), nullptr);
   for (auto i: sorted_insns_)
      if (!i->empty()) {
         auto vec = i->stmt()->find(RTL::RTL_EQUAL::PARTIAL, pc_rel);
         if (!vec.empty()) {
            IF_RTL_TYPE(Const, ((Binary*)(vec.front()))->operand(1), c, {
               auto val = i->next_offset() + c->to_int();
               if (SYSTEM::code_ptr(info_, val))
                  res.insert(val);
            }, {});
         }
      }
   delete pc_rel;

   return res;
}


vector<IMM> Program::scan_fptrs_in_gap() {
   Insn* prev = nullptr;
   vector<IMM> extra_fptrs;
   for (auto it = sorted_insns_.begin(); it != sorted_insns_.end(); ++it) {
      if ((*it)->gap && (prev == nullptr || !prev->gap)) {
         for (; it != sorted_insns_.end() && ((*it)->to_string().compare("nop") == 0); ++it);
         if (it == sorted_insns_.end())
            break;
         if (!checked_fptrs_.contains((*it)->offset())) {
            extra_fptrs.push_back((*it)->offset());
            checked_fptrs_.insert((*it)->offset());
         }
      }
      prev = (*it);
   }
   return extra_fptrs;
}
