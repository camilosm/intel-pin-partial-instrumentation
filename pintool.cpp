#include <cstdio>
#include <fstream>

#include <string>
#include <map>

#include "pin.H"

KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "output file name");

struct Instruction{
    ADDRINT address;
    UINT64 count;

    Instruction(ADDRINT address, UINT64 count = 0): address(address), count(count){}
};

std::map<ADDRINT, Instruction*> instruction_map;

VOID increment_count(ADDRINT address){
    instruction_map[address]->count++;
}

// process program traces
VOID Trace(TRACE trace, VOID* v){
    // iterate over basic blocks in the trace
    for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)){
        // iterate over instructions in the basic block
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
            ADDRINT address = INS_Address(ins);
            instruction_map.insert(std::make_pair(address, new Instruction(address)));
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(increment_count), IARG_ADDRINT, address, IARG_END);
        }
    }
}

void print_instruction_map(FILE* fp){
    for(auto instruction : instruction_map)
        fprintf(fp,"0x%lx:%lu\n", instruction.second->address, instruction.second->count);
}

// called when the application exits
VOID Fini(INT32 code, VOID *v){
    FILE *fp = (FILE*)v;
    print_instruction_map(fp);
    if(fp != stdout)
        fclose(fp);
}

// help message
INT32 Usage(){
    PIN_ERROR("This Pintool counts how many times each instruction is executed\n");
    return -1;
}

int main(int argc, char * argv[]){
    if (PIN_Init(argc, argv))
        return Usage();

    // register trace processing function
    TRACE_AddInstrumentFunction(Trace, 0);

    FILE *fp;
    if(KnobOutputFile.Value().empty())
        fp = stdout;
    else
        fp = fopen(KnobOutputFile.Value().c_str(), "w");

    // register exiting function
    PIN_AddFiniFunction(Fini, fp);

    // start the program, never returns
    PIN_StartProgram();

    return 0;
}