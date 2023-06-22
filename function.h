#include "pin.H"

struct Function{
    ADDRINT address;
    std::string name;
    UINT64 count;

    Function(ADDRINT address, std::string name): address(address), name(name){
        count = 0;
    }
};
