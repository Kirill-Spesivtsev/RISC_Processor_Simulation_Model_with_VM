
#ifndef RISCV_SIM_CPU_H
#define RISCV_SIM_CPU_H

#include "Memory.h"
#include "Decoder.h"
#include "RegisterFile.h"
#include "CsrFile.h"
#include "Executor.h"

class Cpu
{
public:
    Cpu(IMem& mem)
            : _mem(mem)
    {

    }

    void Clock()
    {
        _csrf.Clock();

        if (_mem.getWaitCycles() == 0)
        {
            if (!_waitingInstruction) {
                _mem.Request(this->_ip);
                std::optional<Word> instr = _mem.Response();

                if (instr == std::optional<Word>())
                    return;

                Word instrCode = *instr;
                _instruction = _decoder.Decode(instrCode);
                _rf.Read(_instruction);
                _csrf.Read(_instruction);
                _exe.Execute(_instruction, _ip);
                // Memory request
                _mem.Request(_instruction);
                _memoryWaiting = _mem.Response(_instruction);
                if (!_memoryWaiting) {
                    _waitingInstruction = static_cast<std::unique_ptr<Instruction> &&>(_instruction);
                    return;
                }

            } else {
                _instruction = static_cast<std::unique_ptr<Instruction> &&>(_waitingInstruction);
                _mem.Response(_instruction);
            }
            // Write + Write
            _rf.Write(_instruction);
            _csrf.Write(_instruction);
            _csrf.InstructionExecuted();
            _ip = _instruction->_nextIp;
        }
    }

    void Reset(Word ip)
    {
        _csrf.Reset();
        _ip = ip;
    }

    std::optional<CpuToHostData> GetMessage()
    {
        return _csrf.GetMessage();
    }

private:
    Reg32 _ip;
    Decoder _decoder;
    RegisterFile _rf;
    CsrFile _csrf;
    Executor _exe;
    IMem& _mem;
    bool _memoryWaiting;
    InstructionPtr _instruction;
    InstructionPtr _waitingInstruction;
};


#endif //RISCV_SIM_CPU_H