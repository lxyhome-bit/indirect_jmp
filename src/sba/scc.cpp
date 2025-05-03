/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "../../include/sba/scc.h"
#include "../../include/sba/block.h"
#include "../../include/sba/insn.h"
#include "../../include/sba/rtl.h"

using namespace SBA;
/* --------------------- Strongly Connected Component ----------------------- */
void SCC::dfs(Block* u) {
   u->visited = true;
   Util::Visited.push_back(u);
   for (auto const& [v, c]: u->succ()) {
      v->pred(u);
      if (v->parent != this)
         ext_target.push_back(v);
      else if (!v->visited)
         dfs(v);
   }
   b_list_.push_back(u);
}


void SCC::build_cfg(Block* header) {
   /* reverse postorder for b_list_ */
   Util::Visited.clear();
   dfs(header);
   std::reverse(b_list_.begin(), b_list_.end());
   for (IMM k = 0; k < Util::Visited.count(); ++k)
      Util::Visited.get(k)->visited = false;
}


SCC::~SCC() {
   for (auto b: b_list_)
      b->detach();
}


bool SCC::loop() const {
   /* SCC with more than 1 block */
   if (b_list_.size() != 1)
      return true;
   /* SCC with 1 block pointing to itself */
   else {
      auto u = b_list_.front();
      for (auto const& [v, c]: u->succ())
         if (v == u)
            return true;
      return false;      
   }
}

/*
无循环情况 (!loop()):
   按顺序执行 b_list_ 中的每个基本块。
有循环情况 (loop()):
   如果 iteration_limit == 0（无迭代限制）：
      计算所有块的寄存器预设掩码 mask（preset_regs 的按位或）。
      调用每个块的 preset(mask)，初始化寄存器状态。
      在调试模式下（DLEVEL >= 3），记录被预设的寄存器。
      执行所有块一次。
   如果 iteration_limit > 0（有限迭代）：
      按指定次数 iteration_limit 循环执行所有块。
*/
void SCC::execute(State& s) const {
   s.loc.scc = (SCC*)this;
   if (!loop()) {
      /* execute */
      for (auto b: b_list_)
         b->execute(s);
   }
   else {
      /* until fixpoint (to be supported) */
      /* preset to TOP */
      if (s.config.iteration_limit == 0) {
         uint64_t mask = 0;
         for (auto b: b_list_)
            mask |= b->preset_regs;
         for (auto b: b_list_)
            b->preset(mask);
         #if DLEVEL >= 3
            for (IMM i=bound(REGION::REGISTER,0); i<=bound(REGION::REGISTER,1); ++i)
               if ((mask >> i) & 1)
                  LOG3("preset " << get_id((SYSTEM::Reg)i).to_string());
         #endif
         /* execute */
         for (auto b: b_list_)
            b->execute(s);
      }
      /* iterate n-time */
      else if (s.config.iteration_limit > 0) {
         /* execute */
         for (int i = 0; i < s.config.iteration_limit; ++i)
         for (auto b: b_list_)
            b->execute(s);

      }
   }
   LOG3("==============================================================\n");
}

