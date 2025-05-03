/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#ifndef EXPR_H
#define EXPR_H

#include "rtl.h"
#include "state.h"
#include "common.h"

namespace SBA {
   /* forward declaration */
   class BaseDomain;
   class Compare;
   /* -------------------------------- Expr --------------------------------- */
   class Expr: public RTL {
    public:
    /*
    这个枚举定义了表达式的种类，具体取值如下：
      CONSTANT：常量表达式，例如一个固定数值。
      VAR：变量表达式，表示某个变量。
      ARITHMETIC：算术运算，例如加法、减法等。
      SUBREG：子寄存器表达式，可能表示寄存器的一部分。
      IFELSE：条件表达式，例如三元运算符或 if-else 逻辑。
      CONVERSION：类型转换表达式，例如从整数转为浮点数。
      NOTYPE：无类型，可能用于默认或未定义的情况。
    */
      enum class EXPR_TYPE: char {CONSTANT, VAR, ARITHMETIC, SUBREG,
                                  IFELSE, CONVERSION, NOTYPE};
    /*
    这个枚举定义了表达式的数据类型或操作模式，与硬件或指令集的类型系统密切相关。以下是部分取值及其含义：
      整数类型：
      QI（8位）、HI（16位）、SI（32位）、DI（64位）、TI（128位）。
      浮点类型：
      SF（单精度，32位）、DF（双精度，64位）、XF（扩展精度，80位）、TF（四倍精度，128位）。
      定点或特殊浮点类型：
      FSQI、FSHI、FSSI、FSDI（可能表示特定格式的定点数或浮点数）。
      块类型：
      BLK（通用块）、BLKQI、BLKHI、BLKSI、BLKDI（特定大小的内存块）。
      条件码类型：
      CC、CCZ、CCC、CCO、CCNO、CCGC、CCGOC、CCFP（与标志寄存器或条件码相关）。
      向量类型：
      例如 V1DI（1个64位整数向量）、V2SF（2个单精度浮点向量）、V8QI（8个8位整数向量）、V32QI（32个8位整数向量）等。
      NONE：无模式，可能作为默认值。    
    */
      enum class EXPR_MODE: char {QI, HI, SI, DI, TI, SF, DF, XF, TF,
                                  FSQI, FSHI, FSSI, FSDI,
                                  BLK, BLKQI, BLKHI, BLKSI, BLKDI,
                                  CC, CCZ, CCC, CCO, CCNO, CCGC, CCGOC, CCFP,
                                  V1DI, V1TI, V2DF, V2DI, V2SF, V2SI,
                                  V4DI, V4SF, V4SI, V8HI, V8QI, V8SF, V8SI,
                                  V16HI, V16QI, V32QI, NONE};
      static inline const uint8_t MODE_SZ[43] = {
                                  1,  2,  4,  8, 16, 4,  8, 10, 16,
                                  1,  2,  4,  8,
                                  8,  1,  2,  4,  8,
                                  8,  8,  8,  8,  8,  8, 8, 8,
                                  8, 16, 16, 16,  8,  8,
                                 32, 16, 16, 16,  8, 32, 32,
                                 32, 16, 32, 0};
      static inline const string MODE_STR[43] = {
            ":QI", ":HI", ":SI", ":DI", ":TI", ":SF", ":DF", ":XF", ":TF",
            ":FSQI", ":FSHI", ":FSSI", ":FSDI",
            ":BLK", ":BLKQI", ":BLKHI", ":BLKSI", ":BLKDI",
            ":CC", ":CCZ", ":CCC", ":CCO", ":CCNO", ":CCGC", ":CCGOC", ":CCFP",
            ":V1DI" , ":V1TI" , ":V2DF", ":V2DI", ":V2SF", ":V2SI",
            ":V4DI" , ":V4SF" , ":V4SI", ":V8HI", ":V8QI", ":V8SF", ":V8SI",
            ":V16HI", ":V16QI", ":V32QI", ""};

    private:
      EXPR_TYPE typeExpr_;
      EXPR_MODE modeExpr_;

    protected:
      #if ENABLE_SUPPORT_CONSTRAINT == true
         AbsId expr_id_;
         bool run_expr_id_ = true;
      #endif

    public:
      Expr(EXPR_TYPE type, EXPR_MODE mode): RTL(RTL_TYPE::EXPR),
                                            typeExpr_(type), modeExpr_(mode) {}; 

      /* accessor */
      /*
      simplify()：虚方法，简化表达式（默认返回 this）。
      eval(State& s)：纯虚方法，在给定状态下评估表达式，返回 AbsVal。
      execute(State& s)：空实现（表达式通常不直接修改状态）。
      （条件编译）expr_id(const State&)：返回约束分析的 AbsId。
      clone()：纯虚方法，创建表达式副本。
      find_container()：查找包含指定子表达式的容器。
      */
      EXPR_TYPE expr_type() const {return typeExpr_;};
      EXPR_MODE expr_mode() const {return modeExpr_;};
      uint8_t mode_size() const {return Expr::MODE_SZ[(int)modeExpr_];};
      string mode_string() const {return Expr::MODE_STR[(int)modeExpr_];}
      virtual Expr* simplify() const {return (Expr*)this;};

      /* analysis */
      virtual AbsVal eval(State& s) = 0;
      void execute(State& s) override {};
      #if ENABLE_SUPPORT_CONSTRAINT == true
         virtual const AbsId& expr_id(const State& s) {return expr_id_;};
      #endif

      /* helper */
      virtual Expr* clone() = 0;
      RTL* find_container(RTL* subExpr, const function<bool(const RTL*)>&
                          select) const override {
                             return select(this) && contains(subExpr)?
                                    (RTL*)this: nullptr;
                          };
   };
   /* ------------------------------- Const --------------------------------- */
   class Const: public Expr {
    public:
      enum class CONST_TYPE: char {INTEGER, DOUBLE, VECTOR, ANY};

    private:
      CONST_TYPE typeConst_;
      IMM i_;

    public:
      Const(IMM i): Expr(EXPR_TYPE::CONSTANT, EXPR_MODE::NONE),
                    typeConst_(CONST_TYPE::INTEGER), i_(i) {};
      Const(CONST_TYPE typeConst, Expr* expr);

      /* accessor */
      IMM to_int() const {return i_;};
      CONST_TYPE const_type() const {return typeConst_;};
      string to_string() const override;

      /* analysis */
      AbsVal eval(State& s) override;
      #if ENABLE_SUPPORT_CONSTRAINT == true
         const AbsId& expr_id(const State& s);
      #endif

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      Expr* clone() override;
   };
   /* -------------------------------- Var ---------------------------------- */
   class Var: public Expr {
    public:
      enum class VAR_TYPE: char {MEM, REG};

    private:
      VAR_TYPE typeVar_;

    public:
      Var(VAR_TYPE type, EXPR_MODE mode): Expr(EXPR_TYPE::VAR, mode),
                                          typeVar_(type) {};
      VAR_TYPE var_type() const {return typeVar_;};
   };

  //Mem 表示内存访问表达式（如 *(%rax + 4)）。 
   class Mem: public Var {
    private:
      Expr* addr_;

    public:
      Mem(EXPR_MODE mode, Expr* addr): Var(VAR_TYPE::MEM, mode),
                                       addr_(addr) {};
      ~Mem();

      /* accessor */
      Expr* addr() const {return addr_;};
      string to_string() const override;

      /* analysis */
      AbsVal eval(State& s) override;
      #if ENABLE_SUPPORT_CONSTRAINT == true
         const AbsId& expr_id(const State& s);
      #endif

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      Expr* clone() override;
      bool contains(RTL* subExpr) const override;
   };

  //  Reg 表示寄存器表达式（如 %rax）。
   class Reg: public Var {
    private:
      SYSTEM::Reg r_;

    public:
      Reg(EXPR_MODE mode, SYSTEM::Reg r): Var(VAR_TYPE::REG, mode),
                                        r_(r) {};
      Reg(EXPR_MODE mode, Expr* r);
      ~Reg() {};

      /* accessor */
      SYSTEM::Reg reg() const {return r_;};
      string to_string() const override;

      /* analysis */
      AbsVal eval(State& s) override;
      #if ENABLE_SUPPORT_CONSTRAINT == true
         const AbsId& expr_id(const State& s);
      #endif

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      Expr* clone() override;
   };
   /* ------------------------------- SubReg -------------------------------- */
  //  SubReg 表示寄存器的部分（如 %rax 的低 8 位 %al）。
   class SubReg: public Expr {
    private:
      Expr* expr_;
      int byteNum_;

    public:
      SubReg(EXPR_MODE mode, Expr* expr, int byteNum):
                                         Expr(EXPR_TYPE::SUBREG, mode),
                                         expr_(expr), byteNum_(byteNum) {};
      SubReg(EXPR_MODE mode, Expr* expr, Expr* byteNum);
      ~SubReg();

      /* accessor */
      Expr* expr() const {return expr_;};
      int bytenum() const {return byteNum_;};
      string to_string() const override;

      /* analysis */
      AbsVal eval(State& s) override;

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      Expr* clone() override;
      bool contains(RTL* subExpr) const override;
   };
   /* ------------------------------- IfElse -------------------------------- */
    //  IfElse 表示条件表达式（如 cond ? a : b）。  

   class IfElse: public Expr {
    private:
      Compare* cmp_;
      Expr* if_;
      Expr* else_;

    public:
      IfElse(EXPR_MODE mode, Compare* cmp, Expr* if_expr, Expr* else_expr);
      ~IfElse();

      /* accessor */
      Compare* cmp_expr() const {return cmp_;};
      Expr* if_expr() const {return if_;};
      Expr* else_expr() const {return else_;};
      string to_string() const override;

      /* analysis */
      AbsVal eval(State& s) override;

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      Expr* clone() override;
      bool contains(RTL* subExpr) const override;
   };
   /* ----------------------------- Conversion ------------------------------ */
   class Conversion: public Expr {
    public:
      enum class OP: char {ZERO_EXTRACT, SIGN_EXTRACT, TRUNCATE,
                           STRUNCATE, UTRUNCATE, SFLOAT, UFLOAT,
                           FIX, UFIX, ZERO_EXTEND, SIGN_EXTEND,
                           FLOAT_EXTEND, STRICT_LOW_PART, ANY};
      static inline const string OP_STR[14] =
                     {"zero_extract", "sign_extract", "truncate",
                      "ss_truncate", "us_truncate", "float", "unsigned_float",
                      "fix", "unsigned_fix", "zero_extend", "sign_extend",
                      "float_extend", "strict_low_part", ""};

    private:
      OP typeOp_;
      Expr* expr_;
      Expr* size_;
      Expr* pos_;

    public:
      Conversion(OP type, EXPR_MODE mode, Expr* expr):
                 Expr(EXPR_TYPE::CONVERSION, mode),
                 typeOp_(type), expr_(expr), size_(nullptr), pos_(nullptr) {};
      Conversion(OP type, EXPR_MODE mode, Expr* expr, Expr* size, Expr* pos):
                 Expr(EXPR_TYPE::CONVERSION, mode),
                 typeOp_(type), expr_(expr), size_(size), pos_(pos) {};
      ~Conversion();

      /* accessor */
      OP conv_type() const {return typeOp_;};
      Expr* expr() const {return expr_;};
      Expr* size() const {return size_;};
      Expr* pos() const {return pos_;};
      string to_string() const override;
      Expr* simplify() const override;

      /* analysis */
      AbsVal eval(State& s) override;
      #if ENABLE_SUPPORT_CONSTRAINT == true
         const AbsId& expr_id(const State& s);
      #endif

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      Expr* clone() override;
      bool contains(RTL* subExpr) const override;
   };
   /* ------------------------------- NoType -------------------------------- */
   class NoType: public Expr {
    private:
      string s_;

    public:
      NoType(const string& s): Expr(EXPR_TYPE::NOTYPE, EXPR_MODE::NONE),
                               s_(s) {};
      ~NoType() {};

      /* accessor */
      string to_string() const override {return s_;};

      /* analysis */
      AbsVal eval(State& s) override;

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      Expr* clone() override;
   };

   /* ----------------------------- Arithmetic ------------------------------ */
    //  Arithmetic 是算术操作（一元、二元、比较）的抽象基类。
   class Arithmetic: public Expr {
    public:
      enum class ARITH_TYPE: char {UNARY, BINARY, COMPARE};

    private:
      ARITH_TYPE typeArith_;

    public:
      Arithmetic(ARITH_TYPE type, EXPR_MODE mode):
                                  Expr(EXPR_TYPE::ARITHMETIC, mode),
                                  typeArith_(type) {};
      virtual ~Arithmetic() {};
      ARITH_TYPE arith_type() const {return typeArith_;};
   };
   /* ------------------------------- Unary --------------------------------- */
   class Unary: public Arithmetic {
    public:
      enum class OP: char {NEG, NOT, ABS, SQRT, CLZ, CTZ, BSWAP, ANY};
      static inline const string OP_STR[8] =
                    {"neg", "not", "abs", "sqrt", "clz", "ctz", "bswap", ""};

    private:
      OP op_;
      Expr* operand_;

    public:
      Unary(OP type, EXPR_MODE mode, Expr* operand):
                                     Arithmetic(ARITH_TYPE::UNARY, mode),
                                     op_(type), operand_(operand) {};
      ~Unary();

      /* accessor */
      OP op() const {return op_;};
      Expr* operand() const {return operand_;};
      string to_string() const override;
      bool equal(RTL_EQUAL eq, RTL* _v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* _v) override;

      /* analysis */
      AbsVal eval(State& s) override;

      /* helper */
      Expr* clone() override;
      bool contains(RTL* rtl) const override;
   };                   
   /* ------------------------------- Binary -------------------------------- */
   class Binary: public Arithmetic {
    public:
      enum class OP: char {PLUS, MINUS, MULT, DIV, UDIV, MOD, UMOD, AND, IOR,
                           XOR, ASHIFT, ASHIFTRT, LSHIFTRT, ROTATE, ROTATERT,
                           COMPARE, ANY};
      static inline const string OP_STR[17] =
         {"plus", "minus", "mult", "div", "udiv", "mod", "umod", "and", "ior",
          "xor", "ashift", "ashiftrt", "lshiftrt", "rotate", "rotatert",
          "compare", ""};

    private:
      OP op_;
      array<Expr*,2> operands_;
      #if ENABLE_SUPPORT_CONSTRAINT == true
         AbsPair expr_pair_;
         bool run_expr_pair_ = true;
         array<IMM,2> operand_const_ = {_oo,_oo};
      #endif

    public:
      Binary(OP type, EXPR_MODE mode, Expr* a, Expr* b):
                                     Arithmetic(ARITH_TYPE::BINARY, mode),
                                     op_(type), operands_({a,b}) {};
      ~Binary();

      /* accessor */
      OP op() const {return op_;};
      Expr* operand(uint8_t idx) const {return operands_[idx];};
      string to_string() const override;
      bool equal(RTL_EQUAL eq, RTL* _v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* _v) override;

      /* analysis */
      AbsVal eval(State& s) override;
      #if ENABLE_SUPPORT_CONSTRAINT == true
         const AbsId& expr_id(const State& s);
         const AbsPair& expr_pair(const State& s);
         IMM operand_const(uint8_t idx) const {return operand_const_[idx];};
      #endif

      /* helper */
      Expr* clone() override;
      bool contains(RTL* rtl) const override;
   };
   /* ------------------------------- Compare ------------------------------- */
   class Compare: public Arithmetic {
    public:
      enum class OP: char {EQ, NE, GT, GTU, GE, GEU, LT, LTU, LE, LEU,
                           UNLE, UNLT, UNEQ, LTGT, ORDERED, UNORDERED, ANY};
      static inline const string OP_STR[17] = 
                        {"eq","ne","gt","gtu","ge","geu","lt","ltu","le","leu",
                         "unle","unlt","uneq","ltgt","ordered","unordered",""};

    private:
      OP op_;
      Expr* expr_;

    public:
      Compare(OP op, EXPR_MODE mode, Expr* a):
                                     Arithmetic(ARITH_TYPE::COMPARE, mode),
                                     op_(op), expr_(a) {};
      ~Compare();

      /* accessor */
      OP op() const {return op_;};
      Expr* expr() {return expr_;};
      string to_string() const override;
      bool equal(RTL_EQUAL eq, RTL* _v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* _v) override;

      /* analysis */
      AbsVal eval(State& s) override;

      /* helper */
      Expr* clone() override;
      bool contains(RTL* rtl) const override;
   };
}

#endif
