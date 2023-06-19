#include <chrono>

#include "pin.H"

struct Instruction{
    ADDRINT address;
    std::string mnemonic;
    std::string function;
    std::chrono::duration<double> time;
    UINT64 count;

    Instruction(ADDRINT address, std::string mnemonic, std::string function): address(address), mnemonic(mnemonic), function(function){
        time = std::chrono::duration<double>(0);
        count = 0;
    }
};
