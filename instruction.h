#include "pin.H"

struct Instruction{
    ADDRINT address;
    std::string mnemonic;
    std::string function;
    UINT64 count;

    Instruction(ADDRINT address, std::string mnemonic, std::string function): address(address), mnemonic(mnemonic), function(function){
        count = 0;
    }
};
