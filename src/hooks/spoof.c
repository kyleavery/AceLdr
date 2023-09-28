#include "hooks.h"

typedef struct {
    struct
    {
        D_API( RtlAllocateHeap );
        D_API( NtWaitForSingleObject );

    } ntdll;

    struct
    {
        D_API( InternetConnectA );

    } net;

} API, *PAPI;


SECTION( D ) PVOID RtlAllocateHeap_Hook( PVOID heapHandle, ULONG flags, SIZE_T size )
{
    API     Api;
    PPEB    Peb;
    HANDLE  hNtdll;
    ULONG   Size;

    RtlSecureZeroMemory( &Api, sizeof( Api ) );

    Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    hNtdll = FindModule( H_LIB_NTDLL, Peb, &Size );

    Api.ntdll.RtlAllocateHeap = FindFunction( hNtdll, H_API_RTLALLOCATEHEAP );

    return SPOOF( Api.ntdll.RtlAllocateHeap, hNtdll, Size, heapHandle, C_PTR( U_PTR( flags ) ), C_PTR( U_PTR ( size ) ) );
};

SECTION( D ) LPVOID HeapAlloc_Hook( HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes )
{
    return RtlAllocateHeap_Hook( hHeap, dwFlags, dwBytes );
};

SECTION( D ) HINTERNET InternetConnectA_Hook( HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext )
{
    API     Api;
    PPEB    Peb;
    HANDLE  hNet;
    ULONG   Size;

    RtlSecureZeroMemory( &Api, sizeof( Api ) );

    Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    hNet = FindModule( H_LIB_WININET, Peb, &Size );

    Api.net.InternetConnectA = FindFunction( hNet, H_API_INTERNETCONNECTA );

    return ( HINTERNET )SPOOF( Api.net.InternetConnectA, hNet, Size, hInternet, C_PTR( lpszServerName ), C_PTR( U_PTR( nServerPort ) ), C_PTR( lpszUserName ), C_PTR( lpszPassword ), C_PTR( U_PTR ( dwService ) ), C_PTR( U_PTR( dwFlags ) ), C_PTR( U_PTR( dwContext ) ) );
};

SECTION( D ) NTSTATUS NtWaitForSingleObject_Hook( HANDLE handle, BOOLEAN alertable, PLARGE_INTEGER timeout )
{
    API     Api;
    PPEB    Peb;
    HANDLE  hNtdll;
    ULONG   Size;

    RtlSecureZeroMemory( &Api, sizeof( Api ) );

    Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    hNtdll = FindModule( H_LIB_NTDLL, Peb, &Size );

    Api.ntdll.NtWaitForSingleObject = FindFunction( hNtdll, H_API_NTWAITFORSINGLEOBJECT );

    return ( NTSTATUS )U_PTR( SPOOF( Api.ntdll.NtWaitForSingleObject, hNtdll, Size, handle, C_PTR( U_PTR( alertable ) ), timeout ) );
};
