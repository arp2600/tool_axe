// Copyright (c) 2011-2013, Richard Osborne, All rights reserved
// This software is freely distributable under a derivative of the
// University of Illinois/NCSA Open Source License posted in
// LICENSE.txt and at <http://github.xcore.com/>

#include "FileLoggingTracer.h"
#include "SystemState.h"
#include "ProcessorNode.h"
#include "Core.h"
#include "Resource.h"
#include "Exceptions.h"
#include "Instruction.h"
#include "InstructionProperties.h"
#include "InstructionTraceInfo.h"
#include "InstructionOpcode.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>

using namespace axe;
using namespace Register;

const unsigned mnemonicColumn = 49;
const unsigned regWriteColumn = 87;

static void write_hex(std::fstream &output, uint32_t value) {
  output << std::hex << value << std::dec;
}

FileLoggingTracer::FileLoggingTracer(std::string fileName, bool traceCycles) :
  traceCycles(traceCycles),
  thread(nullptr),
  emittedLineStart(false),
  symInfo(0),
  output (fileName, std::fstream::out),
  pos(output.tellp())
{
}

void FileLoggingTracer::attach(const SystemState &systemState)
{
  symInfo = &systemState.getSymbolInfo();
}

void FileLoggingTracer::align(unsigned column)
{
  uint64_t currentPos = output.tellp() - pos;
  if (currentPos >= column) {
    output << ' ';
    return;
  }
  unsigned numSpaces = column - currentPos;
  for (int i=0; i<numSpaces; i++) {
    output << ' ';
  }
}

void FileLoggingTracer::printLineEnd()
{
  output << '\n';
  pos = output.tellp();
}

void FileLoggingTracer::printThreadName(const Thread &t)
{
  output << t.getParent().getCoreName();
  output << ":t" << t.getNum();
}

void FileLoggingTracer::printLinePrefix(const Node &n)
{
  output << '<';
  output << 'n' << n.getNodeID();
  output << '>';
}

void FileLoggingTracer::printLinePrefix(const Thread &t)
{
  if (traceCycles)
    output << '@' << t.time << ' ';
  output << '<';
  printThreadName(t);
  output << '>';
}

void FileLoggingTracer::printThreadPC(const Thread &t, uint32_t pc)
{
  const Core *core = &t.getParent();
  const ElfSymbol *sym;
  if (t.getParent().isValidRamAddress(pc) &&
      (sym = symInfo->getFunctionSymbol(core, pc))) {
    output << sym->name;
    if (sym->value != pc)
      output << '+' << (pc - sym->value);
    output << "(0x";
    write_hex(output, pc);
    output << ')';
  } else {
    output << "0x";
    write_hex(output, pc);
  }
}

static uint32_t getOperand(const InstructionProperties &properties,
                           const Operands &operands, unsigned i)
{
  return operands.ops[i];
}

static Register::Reg
getOperandRegister(const InstructionProperties &properties,
                   const Operands &ops, unsigned i)
{
  if (i >= properties.getNumExplicitOperands())
    return properties.getImplicitOperand(i - properties.getNumExplicitOperands());
  return static_cast<Register::Reg>(ops.ops[i]);
}

unsigned FileLoggingTracer::parseOperandNum(const char *p, const char *&end)
{
  // Operands are currently restricted to one digit.
  assert(isdigit(*p) && !isdigit(*(p + 1)));
  end = p + 1;
  return *p - '0';
}

void FileLoggingTracer::printInstructionLineStart(const Thread &t, uint32_t pc)
{
  printLinePrefix(*thread);
  output << ' ';
  printThreadPC(t, pc);
  output << ":";
  
  // Align
  align(mnemonicColumn);
  
  // Disassemble instruction.
  InstructionOpcode opcode;
  Operands ops;
  instructionDecode(t.getParent(), pc, opcode, ops, true);
  const InstructionProperties &properties =
  instructionProperties[opcode];
  
  // Special cases.
  // TODO remove this by describing tsetmr as taking an immediate?
  if (opcode == InstructionOpcode::TSETMR_2r) {
    output << "tsetmr ";
    printDestRegister(getOperandRegister(properties, ops, 0));
    output << ", ";
    printSrcRegister(getOperandRegister(properties, ops, 1));
    return;
  }
  
  const char *fmt = instructionTraceInfo[opcode].string;
  for (const char *p = fmt; *p != '\0'; ++p) {
    if (*p != '%') {
      output << *p;
      continue;
    }
    ++p;
    assert(*p != '\0');
    if (*p == '%') {
      output << '%';
      continue;
    }
    enum {
      RELATIVE_NONE,
      DP_RELATIVE,
      CP_RELATIVE,
    } relType = RELATIVE_NONE;
    if (*p == '{') {
      if (*(p + 1) == 'd') {
        assert(std::strncmp(p, "{dp}", 4) == 0);
        relType = DP_RELATIVE;
        p += 4;
      } else {
        assert(std::strncmp(p, "{cp}", 4) == 0);
        relType = CP_RELATIVE;
        p += 4;
      }
    }
    const char *endp;
    unsigned value = parseOperandNum(p, endp);
    p = endp - 1;
    assert(value >= 0 && value < properties.getNumOperands());
    switch (properties.getOperandType(value)) {
    default: assert(0 && "Unexpected operand type");
    case OperandProperties::out:
      printDestRegister(getOperandRegister(properties, ops, value));
      break;
    case OperandProperties::in:
      printSrcRegister(getOperandRegister(properties, ops, value));
      break;
    case OperandProperties::inout:
      printSrcDestRegister(getOperandRegister(properties, ops, value));
      break;
    case OperandProperties::imm:
      switch (relType) {
      case RELATIVE_NONE:
        printImm(getOperand(properties, ops, value));
        break;
      case CP_RELATIVE:
        printCPRelOffset(getOperand(properties, ops, value));
        break;
      case DP_RELATIVE:
        printDPRelOffset(getOperand(properties, ops, value));
        break;
      }
      break;
    }
  }
}

void FileLoggingTracer::printRegWrite(Register::Reg reg, uint32_t value, bool first)
{
  if (first) {
    align(regWriteColumn);
    output << "# ";
  } else {
    output << ", ";
  }
  output << reg << "=0x";
  write_hex(output, value);
}

void FileLoggingTracer::printImm(uint32_t op) {
  output << op;
}

void FileLoggingTracer::instructionBegin(const Thread &t)
{
  assert(!thread);
  assert(!emittedLineStart);
  thread = &t;
  pc = t.getRealPc();
}

void FileLoggingTracer::instructionEnd() {
  assert(thread);
  if (!emittedLineStart) {
    printInstructionLineStart(*thread, pc);
  }
  output << " # ";
  dumpRegisters();

  thread = nullptr;
  emittedLineStart = false;
  printLineEnd();
}

void FileLoggingTracer::dumpRegisters()
{
  for (int i=0; i<16; i++) {
    output << " r" << i << "=0x";
    write_hex(output, thread->readRegisterForTrace(i));
  }
  output << " di=0x" << (thread->isDualIssue() ? "1" : "0");
  output << " time=" << thread->time;
}

void FileLoggingTracer::printSrcRegister(Register::Reg reg)
{
  output << "r" << reg << "(0x";
  write_hex(output, thread->regs[reg]);
  output << ')';
}

void FileLoggingTracer::printDestRegister(Register::Reg reg)
{
  output << "r" << reg;
}

void FileLoggingTracer::printSrcDestRegister(Register::Reg reg)
{
  output << "r" << reg << "(0x";
  write_hex(output, thread->regs[reg]);
  output << ')';
}

void FileLoggingTracer::printCPRelOffset(uint32_t offset)
{
  uint32_t cpValue = thread->regs[CP];
  uint32_t address = cpValue + (offset << 2);
  const Core *core = &thread->getParent();
  const ElfSymbol *sym, *cpSym;
  if ((sym = symInfo->getDataSymbol(core, address)) &&
      sym->value == address &&
      (cpSym = symInfo->getGlobalSymbol(core, "_cp")) &&
      cpSym->value == cpValue) {
    output << sym->name << "(0x";
    write_hex(output, address);
    output << ')';
  } else {
    output << offset;
  }
}

void FileLoggingTracer::printDPRelOffset(uint32_t offset)
{
  uint32_t dpValue = thread->regs[DP];
  uint32_t address = dpValue + (offset << 2);
  const Core *core = &thread->getParent();
  const ElfSymbol *sym, *dpSym;
  if ((sym = symInfo->getDataSymbol(core, address)) &&
      sym->value == address &&
      (dpSym = symInfo->getGlobalSymbol(core, "_dp")) &&
      dpSym->value == dpValue) {
    output << sym->name << "(0x";
    write_hex(output, address);
    output << ')';
  } else {
    output << offset;
  }
}

void FileLoggingTracer::regWrite(Reg reg, uint32_t value)
{
  assert(thread);
  bool first = !emittedLineStart;
  if (!emittedLineStart) {
    printInstructionLineStart(*thread, pc);
  }
  printRegWrite(reg, value, first);
  emittedLineStart = true;
}

void FileLoggingTracer::SSwitchRead(const Node &node, uint32_t retAddress,
                                uint16_t regNum)
{
  assert(!emittedLineStart);
  printLinePrefix(node);
  output << " SSwitch read: ";
  output << "register 0x";
  write_hex(output, regNum);
  output << ", reply address 0x";
  write_hex(output, retAddress);
  printLineEnd();
}

void FileLoggingTracer::
SSwitchWrite(const Node &node, uint32_t retAddress, uint16_t regNum,
             uint32_t value)
{
  assert(!emittedLineStart);
  printLinePrefix(node);
  output << " SSwitch write: ";
  output << "register 0x";
  write_hex(output, regNum);
  output << ", value 0x";
  write_hex(output, value);
  output << ", reply address 0x";
  write_hex(output, retAddress);
  printLineEnd();
}

void FileLoggingTracer::SSwitchNack(const Node &node, uint32_t dest)
{
  assert(!emittedLineStart);
  printLinePrefix(node);
  output << " SSwitch reply: NACK";
  output << ", destintion 0x";
  write_hex(output, dest);
  printLineEnd();
}

void FileLoggingTracer::SSwitchAck(const Node &node, uint32_t dest)
{
  assert(!emittedLineStart);
  printLinePrefix(node);
  output << " SSwitch reply: ACK";
  output << ", destintion 0x";
  write_hex(output, dest);
  printLineEnd();
}

void FileLoggingTracer::SSwitchAck(const Node &node, uint32_t data, uint32_t dest)
{
  assert(!emittedLineStart);
  printLinePrefix(node);
  output << " SSwitch reply: ACK";
  output << ", data 0x";
  write_hex(output, data);
  output << ", destintion 0x";
  write_hex(output, dest);
  printLineEnd();
}

void FileLoggingTracer::
event(const Thread &t, const EventableResource &res, uint32_t pc,
      uint32_t ev)
{
  assert(!emittedLineStart);
  printThreadName(t);
  output << " Event caused by ";
  output << Resource::getResourceName(static_cast<const Resource&>(res).getType());
  output << " 0x";
  write_hex(output, (uint32_t)res.getID());
  printRegWrite(ED, ev, true);
  printLineEnd();
}

void FileLoggingTracer::
interrupt(const Thread &t, const EventableResource &res, uint32_t pc,
          uint32_t ssr, uint32_t spc, uint32_t sed, uint32_t ed)
{
  assert(!emittedLineStart);
  printThreadName(t);
  output << " Interrupt caused by ";
  output << Resource::getResourceName(static_cast<const Resource&>(res).getType());
  output << " 0x";
  write_hex(output, (uint32_t)res.getID());
  printRegWrite(ED, ed, true);
  printRegWrite(SSR, ssr, false);
  printRegWrite(SPC, spc, false);
  printRegWrite(SED, sed, false);
  printLineEnd();
}

void FileLoggingTracer::
exception(const Thread &t, uint32_t et, uint32_t ed,
          uint32_t sed, uint32_t ssr, uint32_t spc)
{
  assert(!emittedLineStart);
  printInstructionLineStart(*thread, pc);
  printLineEnd();
  printThreadName(t);
  output << ' ' << Exceptions::getExceptionName(et) << " exception";
  printRegWrite(ET, et, true);
  printRegWrite(ED, ed, false);
  printRegWrite(SSR, ssr, false);
  printRegWrite(SPC, spc, false);
  printRegWrite(SED, sed, false);
  emittedLineStart = true;
}

void FileLoggingTracer::
syscallBegin(const Thread &t)
{
  assert(!emittedLineStart);
  printLinePrefix(t);
  output << " Syscall ";
}

void FileLoggingTracer::syscall(const Thread &t, const std::string &s) {
  syscallBegin(t);
  output << s << "()";
  printLineEnd();
}

void FileLoggingTracer::syscall(const Thread &t, const std::string &s,
                     uint32_t op0) {
  syscallBegin(t);
  output << s << '(' << op0 << ')';
  printLineEnd();
}

void FileLoggingTracer::dumpThreadSummary(const Core &core)
{
  for (unsigned i = 0; i < NUM_THREADS; i++) {
    const Thread &t = core.getThread(i);
    if (!t.isInUse())
      continue;
    output << "Thread ";
    printThreadName(t);
    if (t.waiting()) {
      if (Resource *res = t.pausedOn) {
        output << " paused on ";
        output << Resource::getResourceName(res->getType());
        output << " 0x";
        write_hex(output, res->getID());
      } else if (t.eeble()) {
        output << " waiting for events";
        if (t.ieble())
          output << " or interrupts";
      } else if (t.ieble()) {
        output << " waiting for interrupts";
      } else {
        output << " paused";
      }
    }
    output << " at ";
    printThreadPC(t, t.getRealPc());
    printLineEnd();
  }
}

void FileLoggingTracer::dumpThreadSummary(const SystemState &system)
{
  for (Node *node : system.getNodes()) {
    if (!node->isProcessorNode())
      continue;
    for (Core *core : static_cast<ProcessorNode*>(node)->getCores()) {
      dumpThreadSummary(*core);
    }
  }
}

void FileLoggingTracer::timeout(const SystemState &system, ticks_t time)
{
  assert(!emittedLineStart);
  output << "Timeout after " << time << " cycles";
  printLineEnd();
  dumpThreadSummary(system);
}

void FileLoggingTracer::noRunnableThreads(const SystemState &system)
{
  assert(!emittedLineStart);
  output << "No more runnable threads";
  printLineEnd();
  dumpThreadSummary(system);
}
