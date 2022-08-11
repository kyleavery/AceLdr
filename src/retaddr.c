//
// https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html
//


#include "include.h"


typedef struct {
    const void* trampoline;     // always JMP RBX
    void* function;             // Target Function
    void* rbx;                  // Placeholder
} PRM, *PPRM;


SECTION( E ) PVOID SpoofRetAddr( PVOID function, HANDLE module, ULONG size, PVOID a, PVOID b, PVOID c, PVOID d, PVOID e, PVOID f, PVOID g, PVOID h )
{
    PVOID Trampoline;

    if( function != NULL )
    {
        Trampoline = FindGadget( module, size );
        if( Trampoline != NULL )
        {
            PRM param = { Trampoline, function };
            return ( 
                        ( 
                            PVOID( * ) (
                                PVOID, PVOID, PVOID, PVOID, PPRM, PVOID, PVOID, PVOID, PVOID, PVOID
                            )
                        )
                        (
                            ( PVOID )Spoof
                        )
                    )
                    ( 
                        a, b, c, d, &param, NULL, e, f, g, h
                    );
        };
    };

    return NULL;
};
