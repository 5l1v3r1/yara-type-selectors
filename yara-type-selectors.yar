/*
 * YARA Type Selectors
 */

/* Private rules ------------------------------------------------------------ */

/* Executables */

private rule PEFILE {
   meta:
      description = "Detects portable executable files in a fuzzy way only by detecting the MZ header and not checking for a PE header"
   condition:
      uint16(0) == 0x5A4D
}

private rule PEFILE_EXACT {
   meta:
      description = "Detects portable executable files in an exact way with MZ string and PE file header"
   condition:
      uint16(0) == 0x5A4D and uint32(uint32(0x3c)) == 0x4550
}

private rule ELFFILE {
   meta:
      description = "Detects Linux executables"
   condition:
      uint32be(0) == 0x7f454c46
}

private rule ELFFILE_EXE {
   meta:
      description = "Detects Linux executables - only executables (no shared libs or something else)"
      reference = "https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#File_header"
   condition:
      uint32be(0) == 0x7f454c46
      and uint16(0x10) == 0x0002
}

private rule MACOSBINARY {
   meta:
      description = "Detects macOS executables"
   condition:
      uint16(0) == 0xfeca or uint16(0) == 0xfacf
}

private rule NET_Executable {
   meta:
      description = "Detects .NET executables"
      author = "dr4k0nia, Florian Roth"
      date = "2023-03-29"
   strings:
      $a1 = "_CorDllMain" ascii
      $a2 = "_CorExeMain" ascii
      $a3 = "mscorlib" ascii fullword
      $a4 = ".cctor" ascii fullword
      $a5 = "System.Private.Corlib" ascii
      $a6 = "<Module>" ascii fullword
      $a7 = "<PrivateImplementationsDetails{" ascii
   condition:
      2 of them
}

/* Other Types */

private rule PKFILE {
   meta:
      description = "Detects ZIP compressed files"
   condition:
      uint16(0) == 0x4B50
}

private rule RTFFILE {
   meta:
      description = "Detects RTF files"
   condition:
      uint32be(0) == 0x7B5C7274
}

private rule OLECF_no_MSI {
   meta:
      description = "Detects OLE 2 compound files (OLECF) which are not MSI files"
   strings:
      $r1 = { 84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46 } /* Class ID */
      $r2 = "msi.dll" fullword ascii
      $r3 = "MsiPatchMetadata" ascii
   condition:
      uint16(0) == 0xCFD0 and not 1 of ($r*)
}

private rule MSI_File {
   meta:
      description = "Detects MSI files"
   strings:
      $r1 = { 84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
   condition:
      uint16(0) == 0xCFD0 and $r1
}

private rule GZIP {
   meta:
      description = "Detects GZIP files"
   condition:
      uint16(0) == 0x8B1F
}

private rule PDF {
   meta:
      description = "Detects PDF files"
   condition:
      uint32(0) == 0x46445025
}

private rule CLASSES_DEX {
   meta:
      description = "Android class lib classes.dex that causes many false positives"
   condition:
      uint32(0) == 0x0a786564
}

private rule CLASSES_DEY {
   meta:
      description = "Android .dey format that causes many false positives"
   condition:
      uint32(0) == 0x0a796564
}

private rule EML_ {
   meta:
      description = "Detects email file bodies"
   strings:
      $fp2 = "Content-Disposition:"
      $fp3 = "Received: by "
   condition:
      1 of them
}

private rule ISO {
   meta:
      description = "Detects ISO files"
      author = "Florian Roth"
   condition:
      uint32(0x8000) == 0x30444301
}

private rule LNK {
   meta:
      description = "Detects Link Files"
      author = "Florian Roth"
   condition:
      uint16(0) == 0x004c and uint32(4) == 0x00021401
}

private rule PNG {
   meta:
      description = "Detects PNG files"
      author = "Florian Roth"
   condition:
      uint32(0) == 0x474e5089
}

private rule PKZIP {
   meta:
      description = "Detects PKZIP packed files - like JAR files"
      author = "Florian Roth"
   condition:
      uint16(0) == 0x4b50
}

private rule DMG {
   meta:
      description = "Detects DMG files"
      author = "Florian Roth"
      date = "2021-10-24"
      reference = "http://newosxbook.com/DMG.html"
   condition:
      uint32(filesize-512) == 0x796c6f6b
}

private rule RAR_Archive {
   meta:
      description = "Detects RAR file "
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2022-07-25"
   condition:
      uint32(0) == 0x21726152
}

private rule SevenZipArchive {
   meta:
      description = "Detects 7z archives"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2022-07-25"
   condition:
      uint32(0) == 0x7a37
}

private rule MSDOS_Stub {
   meta:
      description = "Detects MSDOS stub found in PE executables"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2022-07-25"
   strings:
      $a1 = "!This program cannot be run in DOS mode"
      $a2 = "!This program must be run under Win32"

      /* less common */
      $a3 = "!this is a Windows NT character-mode executable" ascii
      $a4 = "This is a Win32 program."
   condition:
      1 of them
}

private rule ISO_File {
   meta:
      description = "Detects ISO files"
      author = "Florian Roth"
      date = "2023-02-07"
   strings:
      /* CD001 */
      $a1 = { 01 43 44 30 30 31 01 00 }
   condition:
      uint16(0) == 0x0000
      and $a1
}
