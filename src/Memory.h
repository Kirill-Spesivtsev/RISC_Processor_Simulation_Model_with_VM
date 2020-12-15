#ifndef RISCV_SIM_DATAMEMORY_H
#define RISCV_SIM_DATAMEMORY_H

#include "Instruction.h"
#include <iostream>
#include <algorithm>
#include <fstream>
#include <elf.h>
#include <cstring>
#include <vector>
#include <cassert>
#include <map>
#include <list>

using namespace std;

static constexpr size_t vMemSize = 1024 * 1024;
static constexpr size_t pMemSize = 1024 * 1024;
static constexpr size_t pageByteSize = 4096;
static constexpr size_t pageWordSize = pageByteSize / sizeof(Word);
static constexpr size_t vPageNumber = vMemSize / pageWordSize;
static constexpr size_t pPageNumber = pMemSize / pageWordSize;

using Line = array<Word, pageWordSize>;

static Word ToWordAddr(Word ip) { return ip >> 2u; }
static Word ToPageAddr(Word addr) { return (addr & ~(pageByteSize - 1)) / pageByteSize; }
static Word ToPageOffset(Word addr) { return ToWordAddr(addr) & (pageWordSize - 1);}

class VPageTableRow
{

public:
    Word pPageAddress; //адрес в физ памяти
    bool present; //присутствие в памяти
    bool write_read; //доступ на чтение/запись
    bool user_supervisor; //уровень доступа
    bool accessed; // флаг доступа
    bool dirty; // флаг записи
    bool cashing; // запрет кэширования

    VPageTableRow(): VPageTableRow(-1)
    {

    }

    VPageTableRow(Word pPageAddress)
    {
        this->pPageAddress = pPageAddress;
        present = false;
        write_read = true;
        user_supervisor = true;
        cashing = true;
        accessed = false;
        user_supervisor = true;
        dirty = false;
    }
};


class VTable
{
public:
    void Init(VPageTableRow row)
    {
        for (size_t i = 0; i < vPageNumber; i++) {
            this->rows[i] = row;
        }
    }

    VPageTableRow& FindPage(Word vp)
    {
        for(int i = 0; i < rows.size(); i++)
        {
            if (rows[i].pPageAddress == vp)
                return rows[i];
        }
    }

private:
    vector<VPageTableRow> rows;
};


class MemoryStorage {
public:
    vector<Word> pMemory; //зическая память
    vector<Word> vMemory; //виртуальная память
    list<Word> pageLRUList; //список адресов LRU
    VTable vTable; //таблица страниц виртуальной памяти

    MemoryStorage()
    {
        pMemory.resize(pMemSize);
        vMemory.resize(vMemSize);
        VPageTableRow row(0);
        vTable.Init(row);
    }

    bool LoadElf(const std::string &elf_filename) {
        std::ifstream elffile;
        elffile.open(elf_filename, std::ios::in | std::ios::binary);

        if (!elffile.is_open()) {
            std::cerr << "ERROR: load_elf: failed opening file \"" << elf_filename << "\"" << std::endl;
            return false;
        }

        elffile.seekg(0, elffile.end);
        size_t buf_sz = elffile.tellg();
        elffile.seekg(0, elffile.beg);

        // Read the entire file. If it doesn't fit in host memory, it won't fit in the risc-v processor
        std::vector<char> buf(buf_sz);
        elffile.read(buf.data(), buf_sz);

        if (!elffile) {
            std::cerr << "ERROR: load_elf: failed reading elf header" << std::endl;
            return false;
        }

        if (buf_sz < sizeof(Elf32_Ehdr)) {
            std::cerr << "ERROR: load_elf: file too small to be a valid elf file" << std::endl;
            return false;
        }

        // make sure the header matches elf32 or elf64
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *) buf.data();
        unsigned char* e_ident = ehdr->e_ident;
        if (e_ident[EI_MAG0] != ELFMAG0
            || e_ident[EI_MAG1] != ELFMAG1
            || e_ident[EI_MAG2] != ELFMAG2
            || e_ident[EI_MAG3] != ELFMAG3) {
            std::cerr << "ERROR: load_elf: file is not an elf file" << std::endl;
            return false;
        }

        if (e_ident[EI_CLASS] == ELFCLASS32) {
            // 32-bit ELF
            return this->LoadElfSpecific<Elf32_Ehdr, Elf32_Phdr>(buf.data(), buf_sz);
        } else if (e_ident[EI_CLASS] == ELFCLASS64) {
            // 64-bit ELF
            return this->LoadElfSpecific<Elf64_Ehdr, Elf64_Phdr>(buf.data(), buf_sz);
        } else {
            std::cerr << "ERROR: load_elf: file is neither 32-bit nor 64-bit" << std::endl;
            return false;
        }
    }

    Word Read(Word ip){
        return pMemory[VirtToPhysAddress(ip)];
    }

    void Write(Word ip, Word data){
        pMemory[VirtToPhysAddress(ip)] = data;
    }

private:
    template <typename Elf_Ehdr, typename Elf_Phdr>
    bool LoadElfSpecific(char *buf, size_t buf_sz) {
        // 64-bit ELF
        Elf_Ehdr *ehdr = (Elf_Ehdr*) buf;
        Elf_Phdr *phdr = (Elf_Phdr*) (buf + ehdr->e_phoff);
        if (buf_sz < ehdr->e_phoff + ehdr->e_phnum * sizeof(Elf_Phdr)) {
            std::cerr << "ERROR: load_elf: file too small for expected number of program header tables" << std::endl;
            return false;
        }
        auto memptr = reinterpret_cast<char*>(pMemory.data());
        // loop through program header tables
        for (int i = 0 ; i < ehdr->e_phnum ; i++) {
            if ((phdr[i].p_type == PT_LOAD) && (phdr[i].p_memsz > 0)) {
                if (phdr[i].p_memsz < phdr[i].p_filesz) {
                    std::cerr << "ERROR: load_elf: file size is larger than memory size" << std::endl;
                    return false;
                }
                if (phdr[i].p_filesz > 0) {
                    if (phdr[i].p_offset + phdr[i].p_filesz > buf_sz) {
                        std::cerr << "ERROR: load_elf: file section overflow" << std::endl;
                        return false;
                    }

                    // start of file section: buf + phdr[i].p_offset
                    // end of file section: buf + phdr[i].p_offset + phdr[i].p_filesz
                    // start of memory: phdr[i].p_paddr
                    std::memcpy(memptr + phdr[i].p_paddr, buf + phdr[i].p_offset, phdr[i].p_filesz);
                }
                if (phdr[i].p_memsz > phdr[i].p_filesz) {
                    // copy 0's to fill up remaining memory
                    size_t zeros_sz = phdr[i].p_memsz - phdr[i].p_filesz;
                    std::memset(memptr + phdr[i].p_paddr + phdr[i].p_filesz, 0, zeros_sz);
                }
            }
        }
        return true;
    }

    Word VirtToPhysAddress(Word vAddress)
    {
        Word pageAddress = ToPageAddr(vAddress);
        VPageTableRow pageRow = vTable.FindPage(pageAddress);
        if (pageRow.present)//если страница уже в памяти
        {
            pageLRUList.remove(pageAddress);
            pageLRUList.push_back(pageAddress);
        }
        else
        {
            if (pageLRUList.size() < pPageNumber)//если память еще не заполнена
            {
                pageRow.pPageAddress = pageLRUList.size();
                pageRow.present = true;
                pageLRUList.push_back(pageAddress);
            }
            else
            {
                Word vOldPageAddress = pageLRUList.front();
                Word pOldPageAddress = vTable.FindPage(vOldPageAddress).pPageAddress;
                vTable.FindPage(vOldPageAddress).present = false;
                pageLRUList.pop_front();
                pageLRUList.push_back(pageAddress);
                pageRow.pPageAddress = pOldPageAddress;
                pageRow.present = true;
                copy(pMemory.begin() + pOldPageAddress * pageWordSize,
                     pMemory.begin() + pOldPageAddress * pageWordSize + pageWordSize,
                     vMemory.begin() + vOldPageAddress * pageWordSize);
            }
            copy(vMemory.begin() + pageAddress * pageWordSize,
                 vMemory.begin() + pageAddress * pageWordSize + pageWordSize,
                 pMemory.begin() + pageRow.pPageAddress * pageWordSize);
        }
        return pageRow.pPageAddress * pageWordSize + ToPageOffset(vAddress);
    }

};


class IMem
{
public:
    IMem() = default;
    virtual ~IMem() = default;
    IMem(const IMem &) = delete;
    IMem(IMem &&) = delete;

    IMem& operator=(const IMem&) = delete;
    IMem& operator=(IMem&&) = delete;

    virtual void Request(Word ip) = 0;
    virtual std::optional<Word> Response() = 0;
    virtual void Request(InstructionPtr &instr) = 0;
    virtual bool Response(InstructionPtr &instr) = 0;
    virtual void Clock() = 0;
    virtual size_t getWaitCycles() = 0;
};

class UncachedMem : public IMem
{
public:
    explicit UncachedMem(MemoryStorage& amem)
            : _mem(amem)
    {

    }


    void Request(Word ip) override
    {
        if (ip != _requestedIp) {
            _requestedIp = ip;
            _waitCycles = latency;
        }
    }

    std::optional<Word> Response() override
    {
        if (_waitCycles > 0)
            return std::optional<Word>();
        return _mem.Read(_requestedIp);
    }

    void Request(InstructionPtr &instr) override
    {
        if (instr->_type != IType::Ld && instr->_type != IType::St)
            return;

        Request(instr->_addr);
    }

    bool Response(InstructionPtr &instr) override
    {
        if (instr->_type != IType::Ld && instr->_type != IType::St)
            return true;

        if (_waitCycles != 0)
            return false;

        if (instr->_type == IType::Ld)
            instr->_data = _mem.Read(instr->_addr);
        else if (instr->_type == IType::St)
            _mem.Write(instr->_addr, instr->_data);

        return true;
    }


    void Clock() override
    {
        if (_waitCycles > 0)
            --_waitCycles;
    }

    size_t getWaitCycles() override
    {
        return _waitCycles;
    }


private:
    static constexpr size_t latency = 120;
    Word _requestedIp = 0;
    size_t _waitCycles = 0;
    MemoryStorage& _mem;
};


#endif //RISCV_SIM_DATAMEMORY_H