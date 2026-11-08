/*
  MemLink Phase 1 demo YARA rules (authored for this project).

  Purpose: an independent, signature-based corroboration signal for the behavioral rule engine.
  Limits: written from public knowledge of the reflective-loader / Meterpreter family, so a match on this
  known case is expected and is NOT blind validation. Rules contain no case-specific addresses, names or hashes.
  A match is metadata only; it never changes a tier or a conclusion by itself.
*/

rule Reflective_Loader_Export_Name
{
    meta:
        description = "Reflective DLL loader export name present in memory"
        family = "reflective_loader"
    strings:
        $a = "ReflectiveLoader" ascii wide
    condition:
        $a
}

rule Meterpreter_Server_Module_Name
{
    meta:
        description = "Meterpreter server module name string"
        family = "meterpreter"
    strings:
        $x64 = "metsrv.x64.dll" ascii wide
        $x86 = "metsrv.dll" ascii wide
    condition:
        any of them
}

rule Shellcode_x64_Stack_Align_Call_Prologue
{
    meta:
        description = "x64 position-independent shellcode: CLD, stack alignment, call"
        family = "generic_shellcode"
    strings:
        $p = { FC 48 [0-12] 48 83 E4 F0 E8 }
    condition:
        $p
}

rule PE_Header_With_Reflective_Stub
{
    meta:
        description = "MZ header whose bytes also decode as a reflective loader bootstrap (MZ + ARUH stub)"
        family = "reflective_loader"
    strings:
        $h = { 4D 5A 41 52 55 48 89 E5 48 83 EC 20 48 83 E4 F0 }
    condition:
        $h
}
