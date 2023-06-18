#include <cstdio>

#include <fstream>
#include <string>
#include <map>
#include <list>

#include "pin.H"
#include "instlib.H"

INSTLIB::FILTER filter;

KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "output file name");
KNOB<bool> KnobOutputGroup(KNOB_MODE_WRITEONCE, "pintool", "g", "0", "group by function");

struct Instruction{
    ADDRINT address;
    std::string mnemonic;
    std::string function;
    UINT64 count;

    Instruction(ADDRINT address, std::string mnemonic, std::string function): address(address), mnemonic(mnemonic), function(function){
        count = 0;
    }
};

std::map<ADDRINT, Instruction*> instruction_map;

VOID increment_count(ADDRINT address){
    instruction_map[address]->count++;
}

// process program traces
VOID Trace(TRACE trace, VOID* v){
    if(!filter.SelectTrace(trace))
        return;
    // iterate over basic blocks in the trace
    for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)){
        // iterate over instructions in the basic block
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
            ADDRINT address = INS_Address(ins);
            std::string mnemonic = INS_Mnemonic(ins);
            std::string function = PIN_UndecorateSymbolName(RTN_FindNameByAddress(address), UNDECORATION_COMPLETE);
            Instruction* instruction = new Instruction(address, mnemonic, function);
            instruction_map.insert(std::make_pair(address, instruction));
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(increment_count), IARG_ADDRINT, address, IARG_END);
        }
    }
}

void print_instruction_map(FILE* fp, bool group){
    if(!group){
        for(auto pair : instruction_map){
            Instruction* instruction = pair.second;
            fprintf(fp,"0x%lx:%s:%s:%lu\n", instruction->address, instruction->mnemonic.c_str(), instruction->function.c_str(), instruction->count);
        }
    }
    else{
        std::map<std::string, std::list<Instruction*>> instructions_grouped;
        for(auto pair : instruction_map){
            Instruction* instruction = pair.second;
            std::string function = instruction->function;
            instructions_grouped[function].push_back(instruction);
        }
        for(auto pair : instructions_grouped){
            std::string function = pair.first;
            std::list<Instruction*> instruction_list = pair.second;
            fprintf(fp,"Function %s, %lu:\n", function.c_str(), instruction_list.size());
            for(auto instruction : instruction_list)
                fprintf(fp,"0x%lx:%s:%lu\n", instruction->address, instruction->mnemonic.c_str(), instruction->count);
        }
    }
}

// called when the application exits
VOID Fini(INT32 code, VOID *v){
    FILE *fp = (FILE*)v;
    print_instruction_map(fp, KnobOutputGroup.Value());
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

    // needed get more information about associated function names
    PIN_InitSymbols();

    filter.Activate();

    // start the program, never returns
    PIN_StartProgram();

    return 0;
}
