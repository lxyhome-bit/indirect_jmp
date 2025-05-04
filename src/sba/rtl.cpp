/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "../../include/sba/function.h"
#include "../../include/sba/block.h"
#include "../../include/sba/insn.h"
#include "../../include/sba/rtl.h"
#include "../../include/sba/expr.h"
#include "../../include/sba/state.h"
#include "../../include/sba/domain.h"

#include "../../include/sba/macro.h"
#include "../../include/sba/common.h"

using namespace SBA;
// ------------------------------------ RTL ------------------------------------
RTL::operator Statement*() const {
   return typeRTL_==RTL_TYPE::STATEMENT ? (Statement*)this : nullptr;
}

RTL::operator Parallel*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::PARALLEL ?
          (Parallel*)this : nullptr;
}

RTL::operator Sequence*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::SEQUENCE ?
          (Sequence*)this : nullptr;
}

RTL::operator Assign*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::ASSIGN ?
          (Assign*)this : nullptr;
}

RTL::operator Call*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::CALL ?
          (Call*)this : nullptr;
}

RTL::operator Clobber*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::CLOBBER ?
          (Clobber*)this : nullptr;
}

RTL::operator Exit*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::EXIT ?
          (Exit*)this : nullptr;
}

RTL::operator Nop*() const {
   auto t = (Statement*)(*this);
   if (t == nullptr) return nullptr;
   return t->stmt_type()==Statement::STATEMENT_TYPE::NOP ?
          (Nop*)this : nullptr;
}

RTL::operator Expr*() const {
   return typeRTL_ == RTL_TYPE::EXPR ? (Expr*)this : nullptr;
}

RTL::operator Const*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::CONSTANT ? (Const*)this : nullptr;
}

RTL::operator Var*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::VAR ? (Var*)this : nullptr;
}

RTL::operator Mem*() const {
   auto t = (Var*)(*this);
   if (t == nullptr) return nullptr;
   return t->var_type()==Var::VAR_TYPE::MEM ? (Mem*)this : nullptr;
}

RTL::operator Reg*() const {
   auto t = (Var*)(*this);
   if (t == nullptr) return nullptr;
   return t->var_type()==Var::VAR_TYPE::REG ? (Reg*)this : nullptr;
}

RTL::operator Arithmetic*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::ARITHMETIC ?
          (Arithmetic*)this : nullptr;
}

RTL::operator Unary*() const {
   auto t = (Arithmetic*)(*this);
   if (t == nullptr) return nullptr;
   return t->arith_type()==Arithmetic::ARITH_TYPE::UNARY ?
          (Unary*)this : nullptr;
}

RTL::operator Binary*() const {
   auto t = (Arithmetic*)(*this);
   if (t == nullptr) return nullptr;
   return t->arith_type()==Arithmetic::ARITH_TYPE::BINARY ?
          (Binary*)this : nullptr;
}

RTL::operator Compare*() const {
   auto t = (Arithmetic*)(*this);
   if (t == nullptr) return nullptr;
   return t->arith_type()==Arithmetic::ARITH_TYPE::COMPARE ?
          (Compare*)this : nullptr;
}

RTL::operator SubReg*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::SUBREG ? (SubReg*)this : nullptr;
}

RTL::operator IfElse*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::IFELSE ? (IfElse*)this : nullptr;
}

RTL::operator Conversion*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::CONVERSION ?
          (Conversion*)this : nullptr;
}

RTL::operator NoType*() const {
   auto t = (Expr*)(*this);
   if (t == nullptr) return nullptr;
   return t->expr_type()==Expr::EXPR_TYPE::NOTYPE ?
          (NoType*)this : nullptr;
}
// ---------------------------------- Parallel ---------------------------------

// 这个是用来处理并行的指令，
Parallel::~Parallel() {
   for (auto stmt: stmts_)
      delete stmt;
}


string Parallel::to_string() const {
   string s = string("(parallel [").append(stmts_.front()->to_string());
   for (auto it = std::next(stmts_.begin(),1); it != stmts_.end(); ++it)
      s.append(" ").append((*it)->to_string());
   return s.append("])");
}


bool Parallel::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Parallel*)(*v);
   if (v2 == nullptr)
      return false;

   auto it = stmts_.begin();
   auto it2 = v2->stmts().begin();
   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
      case RTL_EQUAL::RELAXED:
      case RTL_EQUAL::STRICT:
         if (stmts_.size() != v2->stmts().size())
            return false;
         for (; it != stmts_.end(); ++it, ++it2)
            if (!(*it)->equal(eq, *it2))
               return false;
         return true;
      default:
         return false;
   }
}


vector<RTL*> Parallel::find(RTL_EQUAL eq, RTL* v) {
   vector<RTL*> vList;
   if (equal(eq, v))
      vList.push_back(this);
   for (auto s: stmts_)
      s->find_helper(eq, v, vList);
   return vList;
}


void Parallel::execute(State& s) {
   #if ENABLE_SUPPORT_CONSTRAINT == true
      for (auto stmt: stmts_)
         stmt->assign_flags(s);
   #endif
   for (auto stmt: stmts_)
      stmt->execute(s);
}


uint64_t Parallel::preset_regs() const {
   uint64_t res = 0;
   for (auto stmt: stmts_)
      res |= stmt->preset_regs();
   return res;
}


bool Parallel::contains(RTL* rtl) const {
   if (this == rtl)
      return true;
   for (auto stmt: stmts_)
      if (stmt->contains(rtl))
         return true;
   return false;
}


RTL* Parallel::find_container(RTL* rtl, const function<bool(const RTL*)>&
select) const {
   if (select(this) && contains(rtl))
      return (RTL*)this;
   for (auto stmt: stmts_) {
      auto v = stmt->find_container(rtl, select);
      if (v != nullptr)
         return v;
   }
   return nullptr;
}
// ---------------------------------- Parallel ---------------------------------
// 处理顺序执行的指令

Sequence::~Sequence() {
   for (auto stmt: stmts_)
      delete stmt;
}


string Sequence::to_string() const {
   string s = string("(sequence [").append(stmts_.front()->to_string());
   for (auto it = std::next(stmts_.begin(),1); it != stmts_.end(); ++it)
      s.append(" ").append((*it)->to_string());
   return s.append("])");
}


bool Sequence::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Sequence*)(*v);
   if (v2 == nullptr)
      return false;

   auto it = stmts_.begin();
   auto it2 = v2->stmts().begin();
   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
      case RTL_EQUAL::RELAXED:
      case RTL_EQUAL::STRICT:
         if (stmts_.size() != v2->stmts().size())
            return false;
         for (; it != stmts_.end(); ++it, ++it2)
            if (!(*it)->equal(eq, *it2))
               return false;
         return true;
      default:
         return false;
   }
}


vector<RTL*> Sequence::find(RTL_EQUAL eq, RTL* v) {
   vector<RTL*> vList;
   if (equal(eq, v))
      vList.push_back(this);
   for (auto stmt: stmts_)
      stmt->find_helper(eq, v, vList);
   return vList;
}


void Sequence::execute(State& s) {
   for (auto stmt: stmts_) {
      /* commit previous stmt before executing current stmt */
      /* last stmt will be committed outside                */
      s.commit_insn();
      stmt->execute(s);
   }
}


uint64_t Sequence::preset_regs() const {
   uint64_t res = 0;
   for (auto stmt: stmts_)
      res |= stmt->preset_regs();
   return res;
}


bool Sequence::contains(RTL* rtl) const {
   if (this == rtl)
      return true;
   for (auto stmt: stmts_)
      if (stmt->contains(rtl))
         return true;
   return false;
}


RTL* Sequence::find_container(RTL* rtl, const function<bool(const RTL*)>&
select) const {
   if (select(this) && contains(rtl))
      return (RTL*)this;
   for (auto stmt: stmts_) {
      auto v = stmt->find_container(rtl, select);
      if (v != nullptr)
         return v;
   }
   return nullptr;
}
// ----------------------------------- Assign ----------------------------------
Assign::~Assign() {
   delete dst_;
   delete src_;
}


string Assign::to_string() const {
   return string("(set ").append(dst_->to_string()).append(" ")
                         .append(src_->to_string()).append(")");
}


bool Assign::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Assign*)(*v);
   if (v2 == nullptr)
      return false;

   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
         return ((dst_ == nullptr || dst_->equal(eq, v2->dst())) &&
                 (src_ == nullptr || src_->equal(eq, v2->src())));
      case RTL_EQUAL::RELAXED:
      case RTL_EQUAL::STRICT:
         return (dst_->equal(eq, v2->dst()) && src_->equal(eq, v2->src()));
      default:
         return false;
   }
}


vector<RTL*> Assign::find(RTL_EQUAL eq, RTL* v) {
   vector<RTL*> vList;
   if (equal(eq, v))
      vList.push_back(this);
   dst_->find_helper(eq, v, vList);
   src_->find_helper(eq, v, vList);
   return vList;
}
void Assign::Execute_ASSIGN(State& state){                                               
   auto destination = dst()->simplify();                               
   auto source = src()->simplify();                                    
   auto size_d = destination->mode_size();                             
   auto size_s = source->mode_size();                                  

   /* dst is register */                                               
   IF_RTL_TYPE(Reg, destination, reg, {                                
      auto aval_s = source->eval(state);                               
      aval_s.mode(size_d);                                             
      if (reg->reg() != SYSTEM::FLAGS) {                               
         state.update(get_id(reg->reg()), aval_s);                     
         UPDATE_VALUE(reg, source, state);                             
      }                                                                
      if (reg->reg() == SYSTEM::STACK_PTR) {                           
         CHECK_UNINIT(state, aval_s, size_d, 0x4);                     
      }                                                                                              
   }, {                                                                
   /* dst is memory */                                                 
   IF_RTL_TYPE(Mem, destination, mem, {                                
      auto aval_addr = mem->addr()->eval(state);                       
      auto init_size = mem->addr()->mode_size();                       
      CHECK_UNINIT(state, aval_addr, init_size, 0x1);                  
      auto aval_s = source->eval(state);                               
      aval_s.mode(size_d);                                             
      if (ABSVAL(BaseLH,aval_addr).top()) {                            
         state.clobber(REGION::STACK);                                 
         state.clobber(REGION::STATIC);                                
      }                                                                
      else if (ABSVAL(BaseLH,aval_addr).notlocal())                    
         state.clobber(REGION::STATIC);                                
      else {                                                           
         IF_MEMORY_ADDR(aval_addr, r, range, {                         
            auto const& l = get_id(r, range.lo());                     
            auto const& h = get_id(r, range.hi());                     
            state.update(l, h, size_d, aval_s);                        
            if (r == REGION::STACK && range == Range::ZERO)            
               CHECK_UNINIT(state, aval_s, size_d, 0x4);               
         });                                                           
      }                                                                
      UPDATE_VALUE(mem, source, state);                                
   }, {                                                                
   /* dst is pc */                                                     
   IF_RTL_TYPE(NoType, destination, no_type, {                         
      if (no_type->to_string().compare("pc") == 0) {                   
         auto aval_s = source->eval(state);                            
         aval_s.mode(size_d);                                          
         CHECK_UNINIT(state, aval_s, size_s, 0x2);                     
         /* handle indirect jumps */                                   
         if (state.loc.insn->indirect_target() != nullptr) {           
            /* update jump tables */                                   
            state.loc.func->target_expr[state.loc.insn->offset()]      
                           = ABSVAL(BaseStride,aval_s).clone();       
            LOG3("update(pc):\n" << aval_s.to_string());               
            /* replace cf target with T::PC */                         
            IF_RTL_TYPE(Reg, source, reg, {                            
               state.update(get_id(reg->reg()),AbsVal(AbsVal::T::PC)); 
            }, {                                                       
            IF_RTL_TYPE(Mem, source, mem, {                            
               auto aval_addr = mem->addr()->eval(state);              
               auto init_size = mem->addr()->mode_size();              
               CHECK_UNINIT(state, aval_addr, init_size, 0x1);         
               IF_MEMORY_ADDR(aval_addr, r, range, {                   
                  auto const& l = get_id(r, range.lo());               
                  auto const& h = get_id(r, range.hi());               
                  state.update(l, h, 8, AbsVal(AbsVal::T::PC));        
               });                                                     
            }, {});                                                    
            });                                                        
         }                                                             
         /* handle conditional jumps */                                
      }                                                                
   }, {});                                                             
   });                                                                 
   });                                                                 
 
   auto this_p = state.get_func()->this_points;

   if(state.get_func()->this_pointer){                    
      
      /*跟踪this指针的流向*/
      
      IF_EXIT(this_p,destination,state,
         it->expr_id(state).operator==(destination->expr_id(state)),Expr*,
         {
         this_p.erase(std::remove(this_p.begin(), this_p.end(), res), this_p.end());
         state.get_func()->this_points = this_p;
      },{
         IF_EXIT(this_p, ,state,
         it->expr_id(state).operator==(source->expr_id(state)),Expr*,
         {
         this_p.push_back(destination); 
         state.get_func()->this_points = this_p;
      },{}
      );}
      );
   }
   /*分析this指针和lea指令*/                                                   
   IF_RTL_TYPE(Reg, source, reg_s,{                                     
      if(reg_s->reg() == SYSTEM::Reg::DI && !state.get_func()->this_pointer && state.lea != 3){                              
         state.get_func()->this_points.push_back(destination);
         state.get_func()->this_pointer = true;                
      }                                                                                   
   },{});
   /*跟踪lea指针的流向,可以处理add 0x10 %rax这样的传递，也是合法的*/
   using LeaDstType = std::pair<IMM, Expr*>;
   auto lea_dst = state.get_func()->lea_dst;

   if(state.lea == 2){
      IF_EXIT(lea_dst,destination,state,
         it.second->expr_id(state).operator==(destination->expr_id(state))&&
         !(it.second->expr_id(state).equal_sym(source->expr_id(state))&&it.second->expr_id(state).reg_expr()&&
         it.second->expr_id(state).offset % 8 == 0),LeaDstType,
         {
         lea_dst.erase(std::remove(lea_dst.begin(), lea_dst.end(), res), lea_dst.end());
         state.get_func()->lea_dst = lea_dst;
      },{IF_EXIT(lea_dst,source,state,
         it.second->expr_id(state).operator==(source->expr_id(state)) || 
         (it.second->expr_id(state).equal_sym(source->expr_id(state))&&it.second->expr_id(state).reg_expr()&&
         it.second->expr_id(state).offset % 8 == 0),LeaDstType,
         {
         LeaDstType aval_s = std::make_pair(res.first,destination);
         lea_dst.erase(std::remove(lea_dst.begin(), lea_dst.end(), res), lea_dst.end());
         lea_dst.push_back(aval_s);
         state.get_func()->lea_dst = lea_dst;
      },{}
      );}
      );
   }
   /*初始化lea指令*/   
   if (state.lea == 1 && source->expr_id(state).const_expr()){
      pair<IMM,Expr*> aval_s = std::make_pair(source->expr_id(state).offset,destination);       
      state.get_func()->lea_dst.push_back(aval_s);
      state.lea = 2;
   }

   /*分析lea指令
   判断lea的指令的流向是否为this指针的地址
   */
   
   bool flag = false;
   LeaDstType res;
   if(state.lea == 2){
      for (auto it : lea_dst){
         for (auto it2 : this_p){
            if (it.second->expr_id(state).easy_depended(it2->expr_id(state))){
               state.lea = 3;
               state.get_func()->this_pointer = false; 
               state.get_func()->vfunc_table = it.first;
            }
         }
      }
   }
}
void Assign::execute(State& s) {
   Execute_ASSIGN(s);
   #if ENABLE_SUPPORT_CONSTRAINT == true
      if (run_assign_flags_)
         assign_flags(s);
   #endif
}


#if ENABLE_SUPPORT_CONSTRAINT == true
   void Assign::assign_flags(const State& s) {
      IF_RTL_TYPE(Reg, dst()->simplify(), reg, {
         if (reg->reg() == SYSTEM::FLAGS) {
            auto& flags = s.loc.block->flags;
            auto bin = (Binary*)(*src()->simplify());
            flags = (bin != nullptr)? AbsFlags(bin->expr_pair(s)): AbsFlags();
            LOG3("update(flags):\n      " << flags.to_string());
         }
      }, {});
      run_assign_flags_ = false;
   }
#endif


uint64_t Assign::preset_regs() const {
   uint64_t res = 0;
   IF_RTL_TYPE(Reg, dst_->simplify(), reg, {
      res |= (1 << get_sym(reg->reg()));
   }, {});
   return res;
}


bool Assign::contains(RTL* rtl) const {
   return this == rtl || dst_->contains(rtl) || src_->contains(rtl);
}


RTL* Assign::find_container(RTL* rtl, const function<bool(const RTL*)>& select)
const {
   if (select(this) && contains(rtl))
      return (RTL*)this;
   auto v = dst_->find_container(rtl, select);
   if (v == nullptr)
      v = src_->find_container(rtl, select);
   return v;
}
// ----------------------------------- Call ------------------------------------
Call::~Call() {
   delete target_;
}


string Call::to_string() const {
   return string("(call ").append(target_->to_string())
                          .append(" (const_int 0))");
}


bool Call::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Call*)(*v);
   if (v2 == nullptr)
      return false;

   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
         return (target_ == nullptr || target_->equal(eq, v2->target()));
      case RTL_EQUAL::RELAXED:
      case RTL_EQUAL::STRICT:
         return (target_->equal(eq, v2->target()));
      default:
         return false;
   }
}


vector<RTL*> Call::find(RTL_EQUAL eq, RTL* v) {
   vector<RTL*> vList;
   if (equal(eq, v))
      vList.push_back(this);
   target_->find_helper(eq, v, vList);
   return vList;
}


void Call::execute(State& s) {
   EXECUTE_CALL(s);
}


bool Call::contains(RTL* rtl) const {
   return this == rtl || target_->contains(rtl);
}


RTL* Call::find_container(RTL* rtl, const function<bool(const RTL*)>& select)
const {
   if (select(this) && contains(rtl))
      return (RTL*)this;
   return target_->find_container(rtl, select);
}
// ----------------------------------- Clobber ---------------------------------
Clobber::~Clobber() {
   delete expr_;
}


string Clobber::to_string() const {
   return string("(clobber ").append(expr_->to_string()).append(")");
}


bool Clobber::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Clobber*)(*v);
   if (v2 == nullptr)
      return false;

   switch (eq) {
      case RTL_EQUAL::OPCODE:
         return true;
      case RTL_EQUAL::PARTIAL:
         return (expr_ == nullptr || expr_->equal(eq, v2->expr()));
      case RTL_EQUAL::RELAXED:
      case RTL_EQUAL::STRICT:
         return (expr_->equal(eq, v2->expr()));
      default:
         return false;
   }
}


vector<RTL*> Clobber::find(RTL_EQUAL eq, RTL* v) {
   vector<RTL*> vList;
   if (equal(eq, v))
      vList.push_back(this);
   expr_->find_helper(eq, v, vList);
   return vList;
}


void Clobber::execute(State& s) {
   IF_RTL_TYPE(Reg, expr_, reg, {
      if (reg->reg() != SYSTEM::FLAGS)
         s.clobber(get_id(reg->reg()));
   }, {});
}


#if ENABLE_SUPPORT_CONSTRAINT == true
void Clobber::assign_flags(const State& s) {
   IF_RTL_TYPE(Reg, expr_, reg, {
      if (reg->reg() == SYSTEM::FLAGS) {
         auto& flags = s.loc.block->flags;
         flags.clear();
         LOG3("update(flags):\n      " << flags.to_string());
      }
   }, {});
}
#endif


uint64_t Clobber::preset_regs() const {
   uint64_t res = 0;
   IF_RTL_TYPE(Reg, expr_, reg, {
      res |= (1 << get_sym(reg->reg()));
   }, {});
   return res;
}


bool Clobber::contains(RTL* rtl) const {
   return this == rtl || expr_->contains(rtl);
}


RTL* Clobber::find_container(RTL* rtl, const function<bool(const RTL*)>& select)
const {
   if (select(this) && contains(rtl))
      return (RTL*)this;
   return expr_->find_container(rtl, select);
}
// ------------------------------------ Exit -----------------------------------
string Exit::to_string() const {
   switch (typeExit_) {
      case EXIT_TYPE::RET:
         return string("(simple_return)");
      case EXIT_TYPE::HALT:
         return string("(halt)");
      default:
         return string("");
   }
}


bool Exit::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Exit*)(*v);
   if (v2 == nullptr)
      return false;

   return true;
}


vector<RTL*> Exit::find(RTL_EQUAL eq, RTL* v) {
   if (equal(eq, v))
      return(vector<RTL*>{this});
   return vector<RTL*>{};
}


RTL* Exit::find_container(RTL* rtl, const function<bool(const RTL*)>& select)
const {
   return select(this) && contains(rtl)? (RTL*)this: nullptr;
}


void Exit::execute(State& s) {
   EXECUTE_EXIT(s);
}
/* ----------------------------------- Nop ---------------------------------- */
bool Nop::equal(RTL_EQUAL eq, RTL* v) const {
   if (v == nullptr)
      return (eq == RTL_EQUAL::PARTIAL);

   auto v2 = (Nop*)(*v);
   if (v2 == nullptr)
      return false;

   return true;
}


vector<RTL*> Nop::find(RTL_EQUAL eq, RTL* v) {
   if (equal(eq, v))
      return(vector<RTL*>{this});
   return vector<RTL*>{};
}


RTL* Nop::find_container(RTL* rtl, const function<bool(const RTL*)>& select)
const {
   return select(this) && contains(rtl)? (RTL*)this: nullptr;
}
