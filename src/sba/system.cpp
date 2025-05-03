/*
   SBA: Static Binary Analysis Framework                          
                                                                  
   Copyright (C) 2018 - 2025 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.                 
*/

#include "../../include/sba/framework.h"
#include "../../include/sba/insn.h"
#include "../../include/sba/system.h"
#include <array>
#include <elf.h>
#include <cstring>
#include <vector>
#include <map>



using std::string;
using std::vector;
using std::unordered_set;
using std::unordered_map;
using std::map;
using std::fstream;
using std::pair;
using std::tuple;
using std::stoull;
using namespace SBA;
using namespace std;


void ELF_x86::load(Object& info, const string& file) {
   string s;
   string cmd;

   /* program headers */
   cmd = string("readelf -Wl ") + file + string(" | grep LOAD")
       + string(" | awk '{print $2 \"\\n\" $3 \"\\n\" $5 \"\\n\" $6}' > ")
       + Framework::d_session + "temp";
   (void)!system(cmd.c_str());

   fstream f1(Framework::d_session + "temp", fstream::in);
   while (getline(f1, s)) {
      auto foffset = stoull(s, nullptr, 16);
      getline(f1, s);
      auto vaddr = stoull(s, nullptr, 16);
      getline(f1, s);
      auto fsize = stoull(s, nullptr, 16);
      getline(f1, s);
      auto msize = stoull(s, nullptr, 16);
      info.phdr.push_back({vaddr, foffset, fsize, msize});
   }
   f1.close();
   std::sort(info.phdr.begin(), info.phdr.end());

   /* raw bytes */
   std::ifstream f2(file, std::ios::in | std::ios::binary);
   info.raw_bytes = vector<uint8_t>(std::istreambuf_iterator<char>(f2),
                                    std::istreambuf_iterator<char>());
   f2.close();

   /* code segments */
   cmd = string("readelf -WS ") + file + string(" | awk '$8 ~/X/'")
       + string(" | awk '{print $4 \"\\n\" $6}' >")
       + Framework::d_session + "temp";
   (void)!system(cmd.c_str());

   fstream f3(Framework::d_session, fstream::in);
   while (getline(f3, s)) {
      auto addr = stoull("0x" + s, nullptr, 16);
      getline(f3, s);
      auto size = stoull("0x" + s, nullptr, 16);
      info.code_segment.push_back({addr, addr+size-1});
   }
   f3.close();
}


uint64_t ELF_x86::read(const Object& info, int64_t offset, uint8_t width) {
   uint64_t final_vaddr = 0;
   uint64_t final_foffset = 0;
   uint64_t final_fsize = 0;
   uint64_t final_msize = 0;
   for (auto const& [vaddr, foffset, fsize, msize]: info.phdr)
      if (vaddr <= (uint64_t)offset) {
         final_vaddr = vaddr;
         final_foffset = foffset;
         final_fsize = fsize;
         final_msize = msize;
      }

   /* uninit values are filled with zero */
   uint64_t dist = (uint64_t)offset - final_vaddr;
   if (final_fsize < dist && dist < final_msize)
      return 0;

   /* address beyond binary bounds */
   uint64_t adj_offset = final_foffset + dist;
   if (adj_offset >= info.raw_bytes.size())
      return 0x8000000080000000;

   uint64_t val = 0;
   for (uint8_t i = 0; i < width; ++i)
      #if ENDIAN == 0
      val += ((uint64_t)info.raw_bytes[adj_offset+i] << (uint64_t)(i<<3));
      #else
      val += ((uint64_t)info.raw_bytes[adj_offset+i] << (uint64_t)((width-1-i)<<3));
      #endif
   return val;
}


bool ELF_x86::code_ptr(const Object& info, IMM ptr) {
   if (!info.insns->empty())
      return info.insns->contains(ptr);
   else {
      for (auto [l,h]: info.code_segment)
         if (l <= ptr && ptr <= h)
            return true;
      return false;
   }
}


unordered_set<IMM> ELF_x86::stored_cptrs(const Object& info, uint8_t size) {
   unordered_set<IMM> cptrs;
   for (IMM offset = 0; offset < (IMM)(info.raw_bytes.size()-size+1); ++offset) {
      auto val = ELF_x86::read(info, offset, size);
      if (ELF_x86::code_ptr(info, val))
         cptrs.insert(val);
   }
   return cptrs;
}


unordered_set<IMM> ELF_x86::definite_fptrs(const Object& info, const string& file) {
   // 等效命令 readelf --dyn-syms a.out | grep 'FUNC' | grep -v 'UND' | awk '{print $2}' | sed 's/^0*//' > /tmp/temp
   // 从动态符号表中提取文件中定义的动态函数的地址。
   auto cmd = string("readelf --dyn-syms ") + file
            + string("| grep 'FUNC' | grep -v 'UND' ")
            + string("| awk '{print $2}' | sed 's/^0*//' > ")
            + Framework::d_session + string("temp; ")
   //等效命令 readelf -Wr a.out | grep 'R_X86_64_RELATIVE\|R_X86_64_IRELATIVE' | awk '{print $4}' | sed 's/^0*//' >> /tmp/temp
   //提取与相对地址重定位相关的目标地址，通常是数据段或函数指针的初始化值。
   // R_X86_64_RELATIVE：表示直接相对地址重定位，通常用于初始化数据段中的指针。
   // R_X86_64_IRELATIVE：表示间接相对地址重定位，通常涉及运行时计算的地址（如函数指针）。
            + string("readelf -Wr ") + file
            + string("| grep 'R_X86_64_RELATIVE\\|R_X86_64_IRELATIVE' ")
            + string("| awk '{print $4}' | sed 's/^0*//' >> ")
            + Framework::d_session + string("temp; ")
   // 等效命令 objdump -d a.out | grep 'callq  ' | grep -v '\*' | grep '^  ' | awk '{print $(NF-1)}' | sort -u >> /tmp/temp
   // 提取反汇编中直接 callq 指令的目标地址，通常是函数入口点或 PLT 条目
            + string("objdump -d ") + file
             + string("| grep 'callq  ' | grep -v '\\*' | grep '^  ' ")
             + string("| awk '{print $(NF-1)}' | sort -u >> ")
             + Framework::d_session + string("temp");
   (void)!system(cmd.c_str());

   string s;
   unordered_set<IMM> fptrs;
   fstream f1(Framework::d_session + "temp", fstream::in);
   while (getline(f1,s)) {
      auto fptr = stoull("0x"+s, nullptr, 16);
      if (ELF_x86::code_ptr(info, fptr))
         fptrs.insert(stoull("0x"+s, nullptr, 16));
   }
   f1.close();

   return fptrs;
}

// ELF_x86::noreturn_fptrs 是一个分析工具，通过解析 ELF 文件的重定位表和导入符号，找出调用不可返回函数的地址。
unordered_set<IMM> ELF_x86::noreturn_fptrs(const string& file) {
   // 过滤出类型为 R_X86_64_JUMP_SLOT 的重定位条目，这些条目通常与动态链接的函数调用（如通过 PLT 表）相关。
   // 从每一行提取第 1 列（偏移地址）和第 5 列（符号名）。
   // 删去前导0。删去版本号
   auto cmd = string("readelf -r ") + file
            + string(" | grep 'R_X86_64_JUMP_SLO' | awk '{print $1, $5}'")
            + string(" | sed 's/^0*//' | cut -d'@' -f1 > ")
            + Framework::d_session + "temp";
   (void)!system(cmd.c_str());
// 筛选出与不可返回函数对应的重定位地址   
   string s;
   unordered_set<IMM> sym_noret;
   // 
   fstream f1(Framework::d_session + "temp", fstream::in);
   while (getline(f1, s)) {
      auto sym_name = s.substr(s.find(" ") + 1, string::npos);
      for (auto const& noret: noreturn_definite)
         if (sym_name.compare(noret) == 0) {
            sym_noret.insert(Util::to_int("0x" + s.substr(0, s.find(" "))));
            break;
         }
   }
   f1.close();

   // 
   unordered_set<IMM> res;
   for (auto [call, sym]: ELF_x86::import_symbols(file))
      if (sym_noret.contains(sym))
         res.insert(call);
   return res;
}

// 将小端数据转换为大端
IMM to_big_endian(IMM val) {
   uint64_t result = val;
   // 需要将结果字节反转
   uint8_t* byte_ptr = reinterpret_cast<uint8_t*>(&result);
   std::reverse(byte_ptr, byte_ptr + sizeof(IMM));  // 反转字节
   return result;
}

//通过.rel.dyn重定位表，找到所有的待重定位的虚表地址
// 虚表会在加载的时候被重定位，而加载到实际的内存中
std::tuple<bool, IMM ,unordered_map<IMM, unordered_set<IMM>>> ELF_x86::vtables_by_rel(const string& file){
   // 实际虚函数地址 -- 虚表中的表项们（可能有多个）
   unordered_map<IMM, unordered_set<IMM>>  res;
   bool striped;
/* 
请根据上面的代码，按照下面的逻辑生成地址：
1.查看elf中的.rel.dyn段，寻找所有的待重定位地址
2.筛选出上述地址中地址处于.data.rel.ro段中的
3.得到的地址再查看地址开始的8字节数据，以该数据为地址，在符号表中查看是否存在
最后得到满足上述3种条件的地址
*/    // 打开文件
   std::ifstream elf_file(file, std::ios::binary);
   if (!elf_file) {
      std::cerr << "Failed to open ELF file\n";
      return {false,0,res};
   }

   // 读取 ELF 文件头
   Elf64_Ehdr elf_header;
   elf_file.read(reinterpret_cast<char*>(&elf_header), sizeof(Elf64_Ehdr));
   if (std::strncmp(reinterpret_cast<char*>(&elf_header.e_ident[0]), "\x7f\x45\x4c\x46", 4) != 0) {
      std::cerr << "Not a valid ELF file\n";
      return {false,0,res};
   }

   // 获取程序头信息并查找 .rel.dyn 段
   std::vector<Elf64_Phdr> program_headers(elf_header.e_phnum);
   elf_file.seekg(elf_header.e_phoff, std::ios::beg);
   elf_file.read(reinterpret_cast<char*>(program_headers.data()), elf_header.e_phnum * sizeof(Elf64_Phdr));
   if (!elf_file) {
      std::cerr << "Failed to read program headers\n";
      return {false,0,res};
   }

   Elf64_Shdr data_rel_ro_section;
   Elf64_Shdr rel_dyn_section;
   
   bool found_data_rel_ro = false;
   std::vector<Elf64_Rela> relocations;

   // 读取 ELF 文件中的节头信息
   std::vector<Elf64_Shdr> section_headers(elf_header.e_shnum);
   elf_file.seekg(elf_header.e_shoff, std::ios::beg);  // 定位到段头表的位置
   elf_file.read(reinterpret_cast<char*>(section_headers.data()), elf_header.e_shnum * sizeof(Elf64_Shdr)); // 读取段头信息
   // if (!elf_file) {
   //    std::cerr << "Failed to read section headers.\n";
   //    return res; // 如果读取失败，则返回空结果
   // }

   // 读取节名称字符串表（.shstrtab）
   Elf64_Shdr shstrtab_section = section_headers[elf_header.e_shstrndx];
   std::vector<char> shstrtab_data(shstrtab_section.sh_size);
   elf_file.seekg(shstrtab_section.sh_offset, std::ios::beg);
   elf_file.read(shstrtab_data.data(), shstrtab_section.sh_size);
   if (!elf_file) {
      std::cerr << "Failed to read .shstrtab\n";
      return {false,0,res};
   }

   // 遍历端头信息，查找".rel.dyn"节
   for (const auto& section : section_headers) {
      if (section.sh_name == 0) continue; // 跳过无效节

      // 获取节的名字，使用 sh_name 来从 .shstrtab 中获取字符串
      std::string section_name(&shstrtab_data[section.sh_name]);
      if (section_name == ".rela.dyn") {
         rel_dyn_section = section;

         elf_file.seekg(rel_dyn_section.sh_addr, std::ios::beg);

         // 获取 .rel.dyn 段的大小
         size_t remaining_size = rel_dyn_section.sh_size;
         
         // 读取重定位信息
         Elf64_Rela relocation;
         while (remaining_size >= sizeof(Elf64_Rela) && elf_file.read(reinterpret_cast<char*>(&relocation), sizeof(Elf64_Rela))) {
            if(relocation.r_info == R_X86_64_RELATIVE){
               relocations.push_back(relocation);
            }
            remaining_size -= sizeof(Elf64_Rela);  // 更新剩余的大小
         }
         
         // 检查读取是否超出了段的大小
         if (remaining_size != 0) {
            std::cerr << "Warning: Read beyond the size of .rel.dyn section." << std::endl;
         }

         break;
      }
   }



   // 遍历段头信息，查找 ".data.rel.ro" 节
   for (const auto& section : section_headers) {
      if (section.sh_name == 0) continue; // 跳过无效节

      // 获取节的名字，使用 sh_name 来从 .shstrtab 中获取字符串
      std::string section_name(&shstrtab_data[section.sh_name]);
      if (section_name == ".data.rel.ro") {
         data_rel_ro_section = section;
         found_data_rel_ro = true;
         break;
      }
   }

   if (!found_data_rel_ro) {
      return {false,0,res};
   }

   std::vector<Elf64_Sym> symbol_table;

   
   // 遍历节头查找符号表节 (.symtab 和 .dynsym)
   for (const auto& section : section_headers) {
      if (section.sh_type == SHT_SYMTAB || section.sh_type == SHT_DYNSYM) {
            // 获取节的名字
            std::string section_name(&shstrtab_data[section.sh_name]);

            // 如果是符号表节（.symtab 或 .dynsym）
            if (section_name == ".symtab" || section_name == ".dynsym") {
               // 读取符号表的内容
               elf_file.seekg(section.sh_offset, std::ios::beg);
               size_t num_symbols = section.sh_size / sizeof(Elf64_Sym);
               
               // 将读取的符号表内容添加到符号表中
               std::vector<Elf64_Sym> section_symbol_table(num_symbols);
               elf_file.read(reinterpret_cast<char*>(section_symbol_table.data()), section.sh_size);

               if (!elf_file) {
                  striped == true;
               }else{
                  striped = false;
               }

               // 将当前符号表合并到总符号表中
               symbol_table.insert(symbol_table.end(), section_symbol_table.begin(), section_symbol_table.end());
            }
      }
   }

   // 计算出.data.rel.ro段的地址偏移
   uint64_t file_offset;
   // 查找地址所在的程序段
   for (const auto& phdr : program_headers) {
      // 只处理载入到内存中的段
      if (phdr.p_type == PT_LOAD) {
         // 获取虚拟地址段的起始地址和文件偏移
         uint64_t segment_vaddr = phdr.p_vaddr;
         uint64_t segment_offset = phdr.p_offset;

         // 检查当前虚拟地址是否位于该段内
         if (data_rel_ro_section.sh_addr >= segment_vaddr && data_rel_ro_section.sh_addr < segment_vaddr + phdr.p_memsz) {
            // 将虚拟地址转换为文件地址
            file_offset =   segment_vaddr - segment_offset;
         }
      }
   }

    // 查找符合条件的重定位地址
    for (const auto& relocation : relocations) {
        uint64_t address = relocation.r_offset;

        // 检查地址是否位于 .data.rel.ro 段内
        if (address >= data_rel_ro_section.sh_addr && address < data_rel_ro_section.sh_addr + data_rel_ro_section.sh_size) {

            // 读取地址起始的8字节数据，作为新地址
            address -= file_offset;
            elf_file.seekg(address, std::ios::beg);
            IMM new_address = 0;
            elf_file.read(reinterpret_cast<char*>(&new_address), sizeof(IMM));
            // new_address = to_big_endian(new_address);
            if(striped)   {
               res[new_address].insert(address);
               continue;
            }

            // 检查符号表中是否有该地址
            for (const auto& symbol : symbol_table) {
                if (symbol.st_value == new_address && ELF64_ST_TYPE(symbol.st_info) == STT_FUNC) {
                    res[new_address].insert(address+file_offset); // 插入符合条件的地址
                    break;
                }
            }
        }
    }

    return {striped,file_offset, res};

}

// 找到以立即数地址进行call 无返回函数的call指令地址
unordered_set<IMM> ELF_x86::noreturn_calls(const string& file) {
   unordered_set<IMM> res;
   auto noret = noreturn_fptrs(file);
   for (auto [offset, target]: ELF_x86::call_insns(file))
      if (noret.contains(target))
         res.insert(offset);
   return res;
}

// 反汇编：调用 objdump 将 ELF 文件反汇编为汇编指令和原始字节。
// 精简汇编代码：清理冗余前缀、替换无效指令、格式化数值，最终生成适合阅读的汇编代码，保存到 f_asm。
// 提取原始字节：将每条指令的机器码（十六进制字节）保存到 f_raw。
// 临时文件管理：使用 Framework::d_session 下的临时文件存储中间结果。
void ELF_x86::disassemble(const string& file, const string& f_asm, const
string& f_raw) {
   /* disassembly */
   string s;
   auto cmd = string("objdump --prefix-addresses -M intel -d ") + file
            + string("| cut -d' ' -f1,3- | cut -d'<' -f1 | cut -d'#' -f1 ")
            + string("| grep '^0' > ") + Framework::d_session + "temp";
   (void)!system(cmd.c_str());

   static array<string,7> rm_prefix = {" bnd ", " lock ", " data16 ",
                        " addr32 ", " rep ", " repz ", " repnz "};
   static array<string,4> rm_pattern = {"*1]", "*1-", "*1+", "+0x0]"};
   static array<string,3> to_hlt = {"int1", "int3", "icebp"};
   static array<string,11> to_nop = {"rex", "(bad)", "FWORD", "?", "riz",
                        " fs ", " ss ", " ds ", " cs ", " gs ", " es "};
   fstream f1(Framework::d_session + "temp", fstream::in);
   fstream f2(f_asm, fstream::out);
   while (getline(f1,s)) {
      auto p1 = s.find_first_not_of("0");
      auto p2 = s.find(" ",p1);
      auto offset = Util::to_int("0x" + s.substr(p1,p2-p1));

      /* skip faulty */
      auto skip_insn = false;
      for (auto const& x: to_nop)
         if (s.find(x) != string::npos) {
            f2 << ".L" << offset << " nop\n";
            skip_insn = true;
            break;
         }
      if (skip_insn)
         continue;

      /* refine */
      for (auto const& x: to_hlt)
         if (s.find(x) != string::npos) {
            s.replace(p2+1, string::npos, "hlt");
            break;
         }
      if (s.find("rep stos")==string::npos && s.find("repz cmps")==string::npos)
         for (auto const& x: rm_prefix) {
            auto it = s.find(x);
            while (it != string::npos) {
               s.erase(it, x.length()-1);
               it = s.find(x);
            }
         }
      for (auto const& x: rm_pattern) {
         p1 = s.find(x);
         while (p1 != string::npos) {
            s.erase(p1, x.length()-1);
            p1 = s.find(x);
         }
      }

      /* prepend 0x to hex */
      auto itc = s.substr(s.find(" ")+1, string::npos);
      p1 = itc.find(" 0");
      if (p1 != string::npos && p1 < itc.length()-2 && itc[p1+2] != 'x') {
         ++p1;
         p2 = itc.find_first_not_of("0",p1);
         auto val = Util::to_int("0x" + itc.substr(p2,string::npos));
         itc.replace(p1, string::npos, std::to_string(val));
      }
      p1 = itc.find(" fff");
      if (p1 != string::npos)
         itc.insert(p1+1, "0x");

      f2 << ".L" << offset << " " << itc << "\n";
   }
   f1.close();
   f2.close();

   /* raw bytes */
   cmd = string("objdump --prefix-addresses --show-raw-insn -d ") + file
       + string(" | grep '^0' | cut -d'\t' -f1 | cut -d' ' -f3-")
       + string(" | awk '{$1=$1;print}' > ") + f_raw;
   (void)!system(cmd.c_str());
}


vector<pair<IMM,IMM>> ELF_x86::import_symbols(const string& file) {
   // 提取出所有包含jmp 和rip的指令 ，即直接跳转
   auto cmd = string("objdump --prefix-addresses --no-show-raw-insn -M intel -d ")
            + file + string(" | grep -P 'jmp.*\\[rip'")
            + string (" | awk '{print $1 \"\\n\" $(NF-1)}'")
            + string(" | sed 's/^0*//' | paste -d ' ' - - > ")
            + Framework::d_session + "temp";
   (void)!system(cmd.c_str());
   // 以键值对的形式存储跳转指令的地址和目标地址
   string s;
   vector<pair<IMM,IMM>> res;
   fstream f1(Framework::d_session + "temp", fstream::in);
   while (getline(f1, s)) {
      auto addr_call = Util::to_int("0x"+s.substr(0,s.find(" ")));
      auto addr_sym = Util::to_int("0x"+s.substr(s.find(" ")+1, string::npos));
      res.push_back({addr_call, addr_sym});
   }
   f1.close();
   return res;
}

// 提取所有call + 立即数地址的指令，将其指令地址和目标地址以键值对存起来
vector<pair<IMM,IMM>> ELF_x86::call_insns(const string& file) {
   auto cmd = string("objdump --prefix-addresses --no-show-raw-insn -M intel -d ")
            + file + string(" | cut -d' ' -f1,3- | grep -P 'call   [0-9]+' ")
            + string (" | awk '{print $1 \"\\n\" $3}'")
            + string(" | sed 's/^0*//' | paste -d ' ' - - > ")
            + Framework::d_session + "temp";
   (void)!system(cmd.c_str());

   string s;
   vector<pair<IMM,IMM>> res;
   fstream f1(Framework::d_session + "temp", fstream::in);
   while (getline(f1, s)) {
      auto insn_call = Util::to_int("0x"+s.substr(0,s.find(" ")));
      auto addr_call = Util::to_int("0x"+s.substr(s.find(" ")+1, string::npos));
      res.push_back({insn_call, addr_call});
   }
   f1.close();
   return res;
}

/*
2：如果匹配 push 指令模式
1：如果匹配栈帧设置模式
0：如果没有匹配任何模式
*/
uint8_t ELF_x86::prolog(const vector<uint8_t>& raw_insn) {
   /* 1-byte push: [0x53], [0x55]                                     */
   /* 2-byte push: [0x41 0x54], [0x41 0x55], [0x41 0x56], [0x41 0x57] */
   /* mov rbp,rsp: [0x48 0x89 0xe5]                                   */
   /* sub rsp,0x3: [0x48 0x83 0xec ...], [0x48 0x81 0xec ...]         */
   if (raw_insn.size() == 1)
      return (raw_insn.at(0)==0x53 || raw_insn.at(0)==0x55)? 2: 0;
   else if (raw_insn.size() == 2)
      return (raw_insn.at(0)==0x41 &&
             (raw_insn.at(1)>=0x54 && raw_insn.at(1)<=0x57))? 2: 0;
   else if (raw_insn.size() >= 3)
      return (raw_insn.at(0)==0x48 &&
            ((raw_insn.at(1)==0x89 && raw_insn.at(2)==0xe5) ||
             (raw_insn.at(1)==0x83 && raw_insn.at(2)==0xec) ||
             (raw_insn.at(1)==0x81 && raw_insn.at(2)==0xec)))? 1: 0;
   return 0;
}

