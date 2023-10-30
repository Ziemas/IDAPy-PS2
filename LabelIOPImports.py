"""
    LabelIOPImports.py:
        Python script for IDA to help label imports/exports in a PS2 IOP module
"""

from idaapi import *
from idautils import *
from idc import *
import json

def FindBytes(startEA, endEA, data):

    # Roll our own find bytes api because IDA's is too complicated (shocker).
    
    # Loop and find the next instance of the search pattern.
    for i in range(startEA, endEA - len(data)):
    
        # Check for the search pattern.
        found = True
        for x in range(len(data)):
            if idc.get_wide_byte(i + x) != data[x]:
                found = False
                break
                
        # Check if the data matches.
        if found == True:
            return i
            
    # If we made it here we did not find the data.
    return idaapi.BADADDR
    

def MakeAndGetString(ea, length=-1, comment=None):
    """
    Creates a string at the specified address and returns the string value.
    :param ea: address to make string at
    :param comment: optional comment to place at the specified address
    :return: the value of the string at the specified address
    """

    # Make the string.
    if length is -1:
        ida_bytes.create_strlit(ea, idc.BADADDR, ida_nalt.STRTYPE_C)
    else:
        ida_bytes.create_strlit(ea, ea + length, ida_nalt.STRTYPE_C)

    # Check if the comment is valid and if so place it at the address.
    if comment is not None:
        idc.set_cmt(ea, comment, 0)

    # Get the string value.
    return ida_bytes.get_strlit_contents(ea, length, ida_nalt.STRTYPE_C).decode("UTF-8").replace('\x00','')
    
    
def MakeAndGetWord(ea, comment=None):
    """
    Creates a word at the specified address and returns the word value.
    :param ea: address to make word at
    :param comment: optional comment to place at the specified address
    :return: the value of the word at the specified address
    """

    # Make the word value.
    ida_bytes.create_data(ea, FF_WORD, 2, ida_idaapi.BADADDR)

    # Check if the comment is valid and if so place it at the address.
    if comment is not None:
        idc.set_cmt(ea, comment, 0)

    # Get the word value.
    return idc.get_wide_word(ea)
    
    
def ModuleVersionToStr(version):
    versionMajor = (version >> 8) & 0xFF
    versionMinor = version & 0xFF
    return "%d.%d" % (versionMajor, versionMinor)
    
    
def GetModuleFunctionList(moduleName, version):

    # Get the file path for the module definition file.
    scriptFile = os.path.dirname(os.path.abspath(__file__)) + ("\\IOP\\%s.json" % moduleName)

    # Try to open the module json file.
    try:
        jsonFile = open(scriptFile, 'r')
    except IOError:
        print("Failed to open '%s' module file!" % scriptFile)
        return None
        
    # Parse and return json file.
    moduleDefinition = json.load(jsonFile)
    jsonFile.close()

    version = float(ModuleVersionToStr(version))
    print("version " + str(version))

    # Try to find the newest version of the exports for the module.
    highestVersion = 0
    for key in moduleDefinition:

        #if float(key) >= version and float(key) > highestVersion:
        if float(key) > float(highestVersion):
            highestVersion = key
            
    # Use the newest export list found.
    if highestVersion != 0:
        return moduleDefinition[highestVersion]
        
    # A suitable module definition for the specified version was not found.
    print("No module definition for '%s' suitable for v%s was found" % (moduleName, version))
    return None
    
    
def LabelImportTable(tableEa, protos):

    # Format the import table descriptor.
    print("Found at 0x%08x" % tableEa)
    ida_bytes.create_data(tableEa, FF_DWORD, 4, ida_idaapi.BADADDR)
    ida_bytes.create_data(tableEa + 4, FF_DWORD, 4, ida_idaapi.BADADDR)
    version = MakeAndGetWord(tableEa + 8)
    ida_bytes.create_data(tableEa + 10, FF_DWORD, 4, ida_idaapi.BADADDR)
    
    #idc.MakeUnkn(tableEa + 12, 4)
    #idc.MakeUnkn(tableEa + 12 + 4, 4)
    importModuleName = MakeAndGetString(tableEa + 12, 8)
    idc.set_name(tableEa, importModuleName + "_stub", idc.SN_NON_PUBLIC)
    
    # Try to find the newest version of the exports for the module.
    exportNameList = GetModuleFunctionList(importModuleName, version)
    
    # Loop and label the import stubs.
    importCount = 0
    importStubPtr = tableEa + 0x14
    while True:
    
        # Get the import stub instructions.
        ins1 = idc.get_wide_word(importStubPtr)
        ins2 = idc.get_wide_word(importStubPtr + 4)
        if ins1 == 0 and ins2 == 0:
            break
            
        # Create a function for the import stub.
        ida_funcs.add_func(importStubPtr, importStubPtr + 8)
        importCount += 1
        
        # Get the import ordinal.
        ordinal = ins2 & 0xFF
        ordinalStr = str(ordinal)
        
        # Try to name the function using the lookup table.
        if exportNameList is not None and ordinalStr in exportNameList:
            ida_name.set_name(importStubPtr, str(exportNameList[ordinalStr]), ida_name.SN_NON_PUBLIC | ida_name.SN_FORCE)
            if exportNameList[ordinalStr] in protos:
               idc.SetType(importStubPtr, protos[exportNameList[ordinalStr]])
        else:
            importName = "%s_%d" % (importModuleName, ordinal)
            ida_name.set_name(importStubPtr, importName, ida_name.SN_NON_PUBLIC)
            
        # Next import stub.
        importStubPtr += 8
        
    # Print the number of imports found.
    print("Found %d imports for '%s' at 0x%08x" % (importCount, importModuleName, tableEa))
        
    return importStubPtr
    
    
def LabelExportTable(tableEa, protos):
    # Format the export table descriptor.
    ida_bytes.create_data(tableEa, FF_DWORD, 4, ida_idaapi.BADADDR)
    ida_bytes.create_data(tableEa + 4, FF_DWORD, 4, ida_idaapi.BADADDR)
    version = MakeAndGetWord(tableEa + 8)
    ida_bytes.create_data(tableEa + 10, FF_DWORD, 4, ida_idaapi.BADADDR)

    #idc.MakeUnkn(tableEa + 12, 4)
    #idc.MakeUnkn(tableEa + 12 + 4, 4)
    importModuleName = MakeAndGetString(tableEa + 12, 8)
    idc.set_name(tableEa, importModuleName + "_stub", idc.SN_NON_PUBLIC)
    
    # Try to find the newest version of the exports for the module.
    exportNameList = GetModuleFunctionList(importModuleName, version)
    
    # Loop and label the exported functions.
    exportCount = 0
    exportPtr = tableEa + 0x14
    while True:
    
        # Get the exported function address.
        funcEA = idc.get_wide_dword(exportPtr)
        if funcEA == 0 and exportCount >= 4:
            break
            
        # Create a function for the export stub.
        ida_funcs.add_func(funcEA, idaapi.BADADDR)
        
        # Try to name the function using the lookup table.
        ordinalStr = str(exportCount)
        if exportNameList is not None and ordinalStr in exportNameList:
            ida_name.set_name(funcEA, str(exportNameList[ordinalStr]), ida_name.SN_NON_PUBLIC | ida_name.SN_FORCE)
            if exportNameList[ordinalStr] in protos:
               idc.SetType(importStubPtr, protos[exportNameList[ordinalStr]])
        else:
        
            importName = "%s_%d" % (importModuleName, exportCount)
            ida_name.set_name(funcEA, importName, ida_name.SN_NON_PUBLIC)
            
        # Next export.
        exportCount += 1
        exportPtr += 4
        
    # Print the number of exports found.
    print("Found %d exports for '%s' at 0x%08x" % (exportCount, importModuleName, tableEa))
    
    
def main():
    types = os.path.dirname(os.path.abspath(__file__)) + "\\IOP\\typedefs.h"
    funcinfo = os.path.dirname(os.path.abspath(__file__)) + "\\IOP\\funcinfo.json"

    idc.parse_decls(types, PT_FILE)

    startEA = 0
    endEA = 0

    # Get the extents of the .text section.
    textSeg = ida_segment.get_segm_by_name(".text")
    if textSeg is None:
    
        # No .text segment found, this means we could be analyzing a flat file, just search the first segment instead.
        textSeg = ida_segment.get_first_seg()

    importTableId = [ 0x00, 0x00, 0xE0, 0x41, 0x00, 0x00, 0x00, 0x00 ]
    exportTableId = [ 0x00, 0x00, 0xC0, 0x41, 0x00, 0x00, 0x00, 0x00 ]

    f = open(funcinfo, "r")
    protos = json.load(f)
    f.close()

    # Search for an export table.
    exportTableEA = FindBytes(textSeg.start_ea, textSeg.end_ea, exportTableId)
    if exportTableEA != idaapi.BADADDR:
    
        # Label the exports table.
        LabelExportTable(exportTableEA, protos)

    # Search the segment for the import table descriptor bytes.
    importTableEA = FindBytes(textSeg.start_ea, textSeg.end_ea, importTableId)
    while importTableEA != idaapi.BADADDR:
     
        # Label the imports.
        LabelImportTable(importTableEA, protos)
        
        # Find next instance.
        importTableEA = FindBytes(importTableEA + len(importTableId), textSeg.end_ea, importTableId)
        
        
main()
