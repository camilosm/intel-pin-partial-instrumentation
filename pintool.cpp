#include <cstdio>

#include <fstream>
#include <string>
#include <set>
#include <map>
#include <list>
#include <numeric>

#include "pin.H"
#include "instlib.H"

#include "instruction.h"
#include "function.h"

INSTLIB::FILTER filter;

KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "output file name");
KNOB<std::string> KnobInstrumentFunction(KNOB_MODE_WRITEONCE, "pintool", "f", "", "instrument by function");
KNOB<bool> KnobOutputGroup(KNOB_MODE_WRITEONCE, "pintool", "g", "0", "group by function");
KNOB<ADDRINT> KnobAddressSet(KNOB_MODE_APPEND, "pintool", "a", "0", "instructions address set");
KNOB<bool> KnobFilterRange(KNOB_MODE_WRITEONCE, "pintool", "r", "0", "enable range of addresses filter");
KNOB<ADDRINT> KnobAddressStart(KNOB_MODE_WRITEONCE, "pintool", "s", "0", "range filter start address");
KNOB<ADDRINT> KnobAddressEnd(KNOB_MODE_WRITEONCE, "pintool", "e", "0", "range filter end address");

std::set<ADDRINT> filter_addresses_set;

std::map<ADDRINT, Instruction*> instruction_map;
std::map<ADDRINT, Function*> function_map;

VOID instruction_count(ADDRINT address){
    instruction_map[address]->count++;
}

VOID function_count(ADDRINT address){
    function_map[address]->count++;
}

// process program traces by instructions
VOID TraceInstructions(TRACE trace, VOID* v){
    if(!filter.SelectTrace(trace))
        return;
    // iterate over basic blocks in the trace
    for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)){
        // iterate over instructions in the basic block
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
            ADDRINT address = INS_Address(ins);
            bool set, in_set, range, in_range;
            set = KnobAddressSet.SetByUser();
            in_set = filter_addresses_set.count(address)>0;
            range = KnobFilterRange.Value();
            in_range = (address >= KnobAddressStart.Value() && address <= KnobAddressEnd.Value());
            if((set && !in_set && !range && !in_range) || (!set && !in_set && range && !in_range) || (set && !in_set && range && !in_range))
                continue;
            std::string mnemonic = INS_Mnemonic(ins);
            std::string function = PIN_UndecorateSymbolName(RTN_FindNameByAddress(address), UNDECORATION_COMPLETE);
            Instruction* instruction = new Instruction(address, mnemonic, function);
            instruction_map.insert(std::make_pair(address, instruction));
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(instruction_count), IARG_ADDRINT, address, IARG_END);
        }
    }
}

// process program traces by functions
VOID TraceFunctions(TRACE trace, VOID* v){
    if(!filter.SelectTrace(trace))
        return;
    // get block head instruction
    INS ins = BBL_InsHead(TRACE_BblHead(trace));
    ADDRINT address = INS_Address(ins);
    bool set, in_set, range, in_range;
    set = KnobAddressSet.SetByUser();
    in_set = filter_addresses_set.count(address)>0;
    range = KnobFilterRange.Value();
    in_range = (address >= KnobAddressStart.Value() && address <= KnobAddressEnd.Value());
    if((set && !in_set && !range && !in_range) || (!set && !in_set && range && !in_range) || (set && !in_set && range && !in_range))
        return;
    std::string name = PIN_UndecorateSymbolName(RTN_FindNameByAddress(address), UNDECORATION_COMPLETE);
    Function* function = new Function(address, name);
    function_map.insert(std::make_pair(address, function));
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(function_count), IARG_ADDRINT, address, IARG_END);
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

void print_function_map(FILE* fp){
    for(auto pair : function_map){
        Function* function = pair.second;
        fprintf(fp,"0x%lx:%s:%lu\n", function->address, function->name.c_str(), function->count);
    }
}

// called when the application exits
VOID Fini(INT32 code, VOID *v){
    FILE *fp = (FILE*)v;
    if(KnobInstrumentFunction.Value().empty())
        print_instruction_map(fp, KnobOutputGroup.Value());
    // else
        // print_function_map(fp);
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
    if(KnobInstrumentFunction.Value().empty())
        TRACE_AddInstrumentFunction(TraceInstructions, 0);
    else{
        TRACE_AddInstrumentFunction(TraceFunctions, 0);
        cout << "instrument by function" << endl;
    }

    FILE *fp;
    if(KnobOutputFile.Value().empty())
        fp = stdout;
    else
        fp = fopen(KnobOutputFile.Value().c_str(), "w");

    // populate set of instruction addresses to instrument
    for(size_t i = 0; i<KnobAddressSet.NumberOfValues(); i++)
        filter_addresses_set.insert(KnobAddressSet.Value(i));

    // register exiting function
    PIN_AddFiniFunction(Fini, fp);

    // needed get more information about associated function names
    PIN_InitSymbols();

    filter.Activate();

    // start the program, never returns
    PIN_StartProgram();

    return 0;
}
