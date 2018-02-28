#include <windows.h>
#include <stdio.h>
#include "ContainerCreate.h"
#include "ContainerTest.h"

void main(int argc, char *argv[])
{
    if(!IsInAppContainer())
    {
        // RunExecutableInContainer(argv[0]);
        RunExecutableInContainer("C:\\Program Files\\nodejs\\node.exe", "\"C:\\Program Files\\nodejs\\node.exe\"", "C:\\Users\\Ultimus\\go\\src\\github.com\\modulesio\\isolator");
    }else{
        RunContainerTests();
    }
    // getchar();
}