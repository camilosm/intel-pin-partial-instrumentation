#include "pin.H"

struct Function{
    std::string name;
    UINT64 count;

    Function(std::string name): name(name){
        count = 0;
    }
};
