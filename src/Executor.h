
#ifndef RISCV_SIM_EXECUTOR_H
#define RISCV_SIM_EXECUTOR_H

#include "Instruction.h"

class Executor
{
public:
    void Execute(InstructionPtr& instr, Word ip)
    {
        switch(instr->_type)
        {
            case IType::Alu: {
                Word processing_result = alu_processing(instr);
                instr->_data = processing_result;
                instr->_nextIp = ip + 4;
                break;
            }
            case IType::Ld:
            {
                instr->_addr = alu_processing(instr);
                instr->_nextIp = ip + 4;
                break;
            }
            case IType::St:
            {
                instr->_addr = alu_processing(instr);
                instr->_data = instr->_src2Val;
                instr->_nextIp = ip + 4;
                break;
            }
            case IType::Csrw:
            {
                instr->_data = instr->_src1Val;
                instr->_nextIp = ip + 4;
                break;
            }
            case IType::Csrr:
            {
                instr->_data = instr->_csrVal;
                instr->_nextIp = ip + 4;
                break;
            }
            case IType::J:
            {
                instr->_data = ip + 4;
            }
            case IType::Br:
            {
                bool processing_result = branching_processing(instr);
                if (processing_result)
                    instr->_nextIp = ip + *instr->_imm;
                else
                    instr->_nextIp = ip + 4;
                break;
            }
            case IType::Jr:
            {
                instr->_data = ip + 4;

                bool processing_result = branching_processing(instr);
                if (processing_result)
                    instr->_nextIp = *instr->_imm + instr->_src1Val;
                else
                    instr->_nextIp = ip + 4;
                break;
            }
            case IType::Auipc:
            {
                instr->_data = ip + *instr->_imm;
                instr->_nextIp = ip + 4;
                break;
            }
        }
    }

private:
    Word alu_processing (InstructionPtr& instr)
    {
        Word first_operand, second_operand;
        bool is_valid = true;

        if (instr->_src1)
            first_operand = instr->_src1Val;
        else
            is_valid = false;

        if (instr->_imm)
            second_operand = *instr->_imm;
        else if (instr->_src2)
            second_operand = instr->_src2Val;
        else
            is_valid = false;

        if (is_valid) {
            switch (instr->_aluFunc)
            {
                case AluFunc::Add:
                    return first_operand + second_operand;
                case AluFunc::Sub:
                    return first_operand - second_operand;
                case AluFunc::And:
                    return first_operand & second_operand;
                case AluFunc::Or:
                    return first_operand | second_operand;
                case AluFunc::Xor:
                    return first_operand ^ second_operand;

                case AluFunc::Slt:
                {
                    int first_value = first_operand, second_value = second_operand;
                    return first_value < second_value;
                }
                case AluFunc::Sltu:
                    return first_operand < second_operand;
                case AluFunc::Sll:
                    return first_operand << (second_operand % 32);
                case AluFunc::Srl:
                    return first_operand >> (second_operand % 32);
                case AluFunc::Sra:
                {
                    int number = first_operand;
                    number = number >> (second_operand % 32);
                    return Word(number);
                }
            }
        }

        return Word();
    }

    bool branching_processing(InstructionPtr& instr)
    {
        Word first_operand, second_operand;
        if (instr->_src1)
            first_operand = instr->_src1Val;
        if (instr->_src2)
            second_operand = instr->_src2Val;

        switch (instr->_brFunc)
        {
            case BrFunc :: Eq:
            {
                if (first_operand == second_operand)
                    return true;
                else
                    return false;
            }
            case BrFunc :: Neq:
            {
                if (first_operand != second_operand)
                    return true;
                else
                    return false;
            }
            case BrFunc :: Lt:
            {
                int first_value = first_operand, second_value = second_operand;
                if (first_value < second_value)
                    return true;
                else
                    return false;
            }
            case BrFunc :: Ltu:
            {
                if (first_operand < second_operand)
                    return true;
                else
                    return false;
            }case BrFunc :: Ge:
            {
                int first_value = first_operand, second_value = second_operand;
                if (first_value >= second_value)
                    return true;
                else
                    return false;
            }
            case BrFunc :: Geu:
            {
                if (first_operand >= second_operand)
                    return true;
                else
                    return false;
            }
            case BrFunc :: AT:
            {
                return true;
            }
            case BrFunc :: NT:
            {
                return false;
            }
        }
    }
};

#endif // RISCV_SIM_EXECUTOR_H
