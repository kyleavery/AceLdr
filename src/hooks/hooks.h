#pragma once

#include "../include.h"

SECTION( D ) HANDLE WINAPI GetProcessHeap_Hook();
SECTION( D ) VOID WINAPI Sleep_Hook( DWORD dwMilliseconds );
SECTION( D ) LPVOID WINAPI HeapAlloc_Hook( HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes );
SECTION( D ) PVOID NTAPI RtlAllocateHeap_Hook( PVOID heapHandle, ULONG flags, SIZE_T size );
SECTION( D ) HINTERNET InternetConnectA_Hook( HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext );
SECTION( D ) NTSTATUS NtWaitForSingleObject_Hook( HANDLE handle, BOOLEAN alertable, PLARGE_INTEGER timeout );
