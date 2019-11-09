#include <iostream>
#include "sha512.h"
 
using std::string;
using std::cout;
using std::endl;
 
int main(int argc, char *argv[])
{
    string input = "grape";
    string output1 = sha512(input);
 
    cout << "sha512('"<< input << "'):" << output1 << endl;
    return 0;
}