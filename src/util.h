#pragma once

SECTION( E ) UINT32 HashString( PVOID buffer, ULONG size );
SECTION( E ) PVOID FindModule( ULONG hash, PPEB peb, PULONG size );
SECTION( E ) VOID LdrProcessIat( PVOID image, PVOID directory );
SECTION( E ) VOID LdrProcessRel( PVOID image, PVOID directory, PVOID imageBase );
SECTION( E ) VOID LdrHookImport( PVOID image, PVOID directory, ULONG hash, PVOID function );
SECTION( E ) PVOID FindFunction( PVOID image, ULONG hash );
SECTION( E ) PVOID FindGadget( LPBYTE module, ULONG size );

