#include "hooks.h"

SECTION( D ) HANDLE GetProcessHeap_Hook()
{
    return ( ( PSTUB )OFFSET( Stub ) )->Heap;
};
