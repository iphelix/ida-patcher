#!/usr/bin/env python
#
# IDA Patcher is a plugin for Hex-Ray's IDA Pro disassembler designed to 
# enhance IDA's ability to patch binary files and memory. The plugin is 
# useful for tasks related to malware analysis, exploit development as well
# as bug patching. IDA Patcher blends into the standard IDA user interface
# through the addition of a subview and several menu items. 

IDAPATCHER_VERSION = "1.2"

# Copyright (C) 2014 Peter Kacherginsky
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software without 
#    specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# IDA libraries
import idaapi
import idautils
import idc
from idaapi import Form, Choose2, plugin_t

# Python modules
import os
import shutil
import struct
import binascii


#--------------------------------------------------------------------------
# Forms
#--------------------------------------------------------------------------
class PatchRestoreForm(Form):
    """
    Form to aid in restoring patched bytes to their original values.
    """
    def __init__(self, addr_str, fpos_str, patch_str, org_str):
        Form.__init__(self, 
r"""BUTTON YES* Restore
BUTTON CANCEL Cancel
Restore patch bytes

Address        {strAddr}
File offset    {strFpos}
<:{strOrg}>
""", {
        'strAddr': Form.StringLabel(addr_str),
        'strFpos': Form.StringLabel(fpos_str),
        'strOrg': Form.MultiLineTextControl(text=org_str, flags = Form.MultiLineTextControl.TXTF_FIXEDFONT | Form.MultiLineTextControl.TXTF_READONLY),

        })

        self.Compile()

#--------------------------------------------------------------------------
class PatchEditForm(Form):
    """
    Form to edit patched bytes.
    """
    def __init__(self, addr_str, fpos_str, patch_str, org_str):
        Form.__init__(self,
r"""Edit patch bytes

Address        {strAddr}
File offset    {strFpos}
<:{strPatch}>
""", {
        'strAddr':  Form.StringLabel(addr_str),
        'strFpos':  Form.StringLabel(fpos_str),
        'strPatch': Form.MultiLineTextControl(text=patch_str, flags = Form.MultiLineTextControl.TXTF_FIXEDFONT),
        })

        self.Compile()

#--------------------------------------------------------------------------
class PatchApplyForm(Form):
    """
    Form to prompt for target file, backup file, and the address
    range to save patched bytes.
    """
    def __init__(self, start_ea, end_ea, org_file, bkp_file):
        Form.__init__(self,
r"""Apply patches to input file

{FormChangeCb}
<##Start EA   :{intStartEA}>
<##End EA     :{intEndEA}>
<##Input file :{orgFile}>
<##Backup file:{bkpFile}>

<##Create backup:{rBackup}>
<##Restore original bytes:{rRestore}>{cGroup1}>
""", {
        'intStartEA': Form.NumericInput(swidth=40,tp=Form.FT_ADDR,value=start_ea),
        'intEndEA': Form.NumericInput(swidth=40,tp=Form.FT_ADDR,value=end_ea),
        'orgFile': Form.FileInput(swidth=50, open=True, value=org_file),
        'bkpFile': Form.FileInput(swidth=50, open=True, value=bkp_file),
        'cGroup1': Form.ChkGroupControl(("rBackup", "rRestore")),
        'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
        })

        self.Compile()

    def OnFormChange(self, fid):
        # Set initial state
        if fid == -1:
            self.EnableField(self.bkpFile, False)

        # Toggle backup checkbox
        elif fid == self.rBackup.id:
            self.rBackup.checked = not self.rBackup.checked
            self.EnableField(self.bkpFile, self.rBackup.checked)

        # Toggle restore checkbox
        elif fid == self.rRestore.id:
            self.rRestore.checked = not self.rRestore.checked

        return 1

#--------------------------------------------------------------------------
class PatchFillForm(Form):
    """
    Form to fill a range of addresses with a specified byte value.
    """
    def __init__(self, start_ea, end_ea, fill_value):

        Form.__init__(self,
r"""BUTTON YES* Fill
Fill bytes

<##Start EA   :{intStartEA}>
<##End EA     :{intEndEA}>
<##Value      :{intPatch}>
""", {
        'intStartEA': Form.NumericInput(swidth=40,tp=Form.FT_ADDR,value=start_ea),
        'intEndEA': Form.NumericInput(swidth=40,tp=Form.FT_ADDR,value=end_ea),
        'intPatch': Form.NumericInput(swidth=40,tp=Form.FT_HEX,value=fill_value),
        })

        self.Compile()

class DataImportForm(Form):
    """
    Form to import data of various types into selected area.
    """
    def __init__(self, start_ea, end_ea):
        Form.__init__(self,
r"""BUTTON YES* Import
Import data

{FormChangeCb}
<##Start EA   :{intStartEA}>
<##End EA     :{intEndEA}>

Import type:                    Patching options:
<hex string:{rHex}><##Trim to selection:{cSize}>{cGroup}>
<string literal:{rString}>
<binary file:{rFile}>{rGroup}>

<:{strPatch}>
<##Import BIN file:{impFile}>
""", {        
        'intStartEA': Form.NumericInput(swidth=40,tp=Form.FT_ADDR,value=start_ea),
        'intEndEA': Form.NumericInput(swidth=40,tp=Form.FT_ADDR,value=end_ea),

        'cGroup': Form.ChkGroupControl(("cSize",)),
        'rGroup': Form.RadGroupControl(("rHex", "rString", "rFile")),

        'strPatch': Form.MultiLineTextControl(swidth=80, flags=Form.MultiLineTextControl.TXTF_FIXEDFONT),
        'impFile': Form.FileInput(swidth=50, open=True),

        'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
        })

        self.Compile()

    def OnFormChange(self, fid):
        # Form initialization
        if fid == -1:
            self.SetFocusedField(self.strPatch)
            self.EnableField(self.strPatch, True)
            self.EnableField(self.impFile, False)

        # Form OK pressed
        elif fid == -2:
            pass

        # Form from text box
        elif fid == self.rHex.id or fid == self.rString.id:
            self.SetFocusedField(self.strPatch)
            self.EnableField(self.strPatch, True)
            self.EnableField(self.impFile, False)

        # Form import from file
        elif fid == self.rFile.id:
            self.SetFocusedField(self.rFile)
            self.EnableField(self.impFile, True)
            self.EnableField(self.strPatch, False)

        return 1

#--------------------------------------------------------------------------
# Chooser
#--------------------------------------------------------------------------
class PatchView(Choose2):
    """
    Chooser class to display and manage patched bytes in the database.
    """
    def __init__(self):
        Choose2.__init__(self,
                         "Patches",
                         [ ["Address",  10 | Choose2.CHCOL_HEX], 
                           ["Name",     18 | Choose2.CHCOL_PLAIN], 
                           ["Size",      4 | Choose2.CHCOL_DEC], 
                           ["Modified", 10 | Choose2.CHCOL_HEX],
                           ["Original", 10 | Choose2.CHCOL_HEX], 
                           ["Comment",  30 | Choose2.CHCOL_PLAIN]
                         ],
                         flags = Choose2.CH_MULTI_EDIT)

        self.popup_names = ["Insert", "Delete", "Edit", "Refresh"]
        
        self.icon = 47

        # Items for display and corresponding data
        # NOTE: Could become desynchronized, so to avoid this
        #       refresh the view after each change.
        self.items = []
        self.items_data  = []

        # Initialize/Refresh the view
        self.refreshitems()

        # Data members
        self.patch_file = None
        self.restore = False

        # Command callbacks
        self.cmd_apply_patches = None
        self.cmd_restore_bytes = None

    def show(self):
        # Attempt to open the view
        if self.Show() < 0: return False

        # Add extra context menu commands
        # NOTE: Make sure you check for duplicates.
        if self.cmd_apply_patches == None:
            self.cmd_apply_patches = self.AddCommand("Apply patches to input file...", flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_NO_SELECTION, icon=27)
        if self.cmd_restore_bytes == None:
            self.cmd_restore_bytes = self.AddCommand("Restore original byte(s)...", flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_MULTI_SELECTION, icon=139)

        return True

    # Patch byte visitor callback to apply the patches
    # NOTE: Only bytes with fpos > -1 can be applied.
    def apply_patch_byte(self, ea, fpos, org_val, patch_val):
        if fpos != -1:
            self.patch_file.seek(fpos)

            if self.restore:
                self.patch_file.write(struct.pack('B', org_val))
            else:
                self.patch_file.write(struct.pack('B', patch_val))

        return 0

    # Patch byte visitor callback to collect and aggregate bytes
    def get_patch_byte(self, ea, fpos, org_val, patch_val):

        # Aggregate contiguous bytes (base ea + length)
        # NOTE: Looking at the last item [-1] is sufficient
        #       since we are dealing with sorted data.
        if len(self.items_data) and (ea - self.items_data[-1][0] == self.items_data[-1][2]):

            # Increment length
            self.items_data[-1][2] += 1
            self.items[-1][2] = str(self.items_data[-1][2])

            # Append patched bytes
            self.items_data[-1][3].append(patch_val)
            self.items[-1][3] = " ".join(["%02X" % x for x in self.items_data[-1][3]])

            # Append original bytes
            self.items_data[-1][4].append(org_val)
            self.items[-1][4] =  " ".join(["%02X" % x for x in self.items_data[-1][4]])


        # Add new patch byte to the list
        else:

            name = SegName(ea)

            if GetFunctionName(ea) or Name(ea):
                name += ": %s" % GetFunctionName(ea) or Name(ea)


            comment = Comment(ea) or RptCmt(ea) or ""
            # DATA STORAGE FORMAT:      address, function / fpos, len,    patched byte(s), original byte(s), comments
            self.items.append(     ["%08X" % ea,            name, "1", "%02X" % patch_val, "%02X" % org_val, comment])
            self.items_data.append([         ea,            fpos,   1,        [patch_val],        [org_val], None]   )

        return 0

    def refreshitems(self):
        self.items_data = []
        self.items = []
        idaapi.visit_patched_bytes(0, idaapi.BADADDR, self.get_patch_byte)

    def OnCommand(self, n, cmd_id):

        # Apply patches to a file
        if cmd_id == self.cmd_apply_patches:

            # Set initial start/end EA values
            start_ea = 0x0
            end_ea = idaapi.cvar.inf.maxEA

            # Set initial output file values
            org_file = GetInputFilePath()
            bkp_file = "%s.bak" % org_file

            # Create the form
            f = PatchApplyForm(start_ea, end_ea, org_file, bkp_file)

            # Execute the form
            ok = f.Execute()
            if ok == 1:
                # Get restore checkbox
                self.restore = f.rRestore.checked

                # Get updated ea max/min
                start_ea = f.intStartEA.value
                end_ea = f.intEndEA.value

                # Get updated file path
                new_org_file = f.orgFile.value

                # Backup the file before replacing
                if f.rBackup.checked:
                    bkp_file = f.bkpFile.value
                    shutil.copyfile(org_file, bkp_file)

                # Apply patches
                try:
                    self.patch_file = open(new_org_file,'rb+')
                except Exception, e:
                    idaapi.warning("Cannot update file '%s'" % new_org_file)
                else:
                    r = idaapi.visit_patched_bytes(start_ea, end_ea, self.apply_patch_byte)
                    self.patch_file.close()
                    self.restore = False

                    # Update db input file, so we are working
                    # with a patched version.
                    #if not org_file == new_org_file:
                    #    idaapi.set_root_filename(new_org_file)
                    #    org_file = new_org_file

            # Dispose the form
            f.Free()

        # Restore selected byte(s)
        elif cmd_id == self.cmd_restore_bytes:

            # List start/end
            if n == -2 or n ==-3:
                return 1

            elif not len(self.items) > 0:
                idaapi.warning("There are no patches to restore.")
                return 1

            # Nothing selected
            elif n == -1:
                idaapi.warning("Please select bytes to restore.")
                return 1

            ea = self.items_data[n][0]
            fpos =  self.items_data[n][1]
            buf = self.items_data[n][4]

            addr_str = "%#x" % ea
            fpos_str = "%#x" % fpos if fpos != -1 else "N/A"  
            patch_str = self.items[n][3]
            org_str = self.items[n][4]

            # Create the form
            f = PatchRestoreForm(addr_str, fpos_str, patch_str, org_str)

            # Execute the form
            ok = f.Execute()
            if ok == 1:

                # Restore original bytes
                idaapi.put_many_bytes(ea, struct.pack("B"*len(buf), *buf))

                # Refresh all IDA views
                self.refreshitems()

            # Dispose the form
            f.Free()

        return 1

    def OnClose(self):
        self.cmd_apply_patches = None
        self.cmd_restore_bytes = None

    def OnEditLine(self, n):

        # Empty list
        if n == -1:
            return

        # Multiselect START_SEL/END_SEL protocol
        if n == -2 or n ==-3:
            return

        ea = self.items_data[n][0]
        fpos =  self.items_data[n][1]
        patch_buf = self.items_data[n][3]
        orig_buf = self.items_data[n][4]

        addr_str = "%#x" % ea
        fpos_str = "%#x" % fpos if fpos != -1 else "N/A"     
        patch_str = self.items[n][3]
        org_str = self.items[n][4]    

        # Create the form
        f = PatchEditForm(addr_str, fpos_str, patch_str, org_str)

        # Execute the form
        ok = f.Execute()
        if ok == 1:

            # Convert hex bytes to binary
            buf = f.strPatch.value
            buf = buf.replace(' ','')       # remove spaces
            buf = buf.replace('\\x','')     # remove '\x' prefixes
            buf = buf.replace('0x','')      # remove '0x' prefixes
            try:
                buf = binascii.unhexlify(buf)   # convert to bytes
            except Exception, e:
                idaapi.warning("Invalid input: %s" % e)
                f.Free()
                return

            # Restore original bytes first
            idaapi.put_many_bytes(ea, struct.pack("B"*len(orig_buf), *orig_buf))

            # Now apply newly patched bytes
            idaapi.patch_many_bytes(ea, buf)

            # Refresh all IDA views
            self.refreshitems()

        # Dispose the form
        f.Free()

    def OnSelectLine(self, n):
        idaapi.jumpto(self.items_data[n][0])

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetIcon(self, n):

        # Empty list
        if not len(self.items) > 0:
            return -1

        if self.items_data[n][1] == -1:
            return 138
        else:
            return 137

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, n):
        self.refreshitems()
        return n

    def OnActivate(self):
        self.refreshitems()

#--------------------------------------------------------------------------
# Manager
#--------------------------------------------------------------------------
class PatchManager():
    """ Class that manages GUI forms and patching methods of the plugin. """
    
    def __init__(self): 
        self.addmenu_item_ctxs = list()
        self.patch_view = PatchView()

    #--------------------------------------------------------------------------
    # Menu Items
    #--------------------------------------------------------------------------
    def add_menu_item_helper(self, menupath, name, hotkey, flags, pyfunc, args):

        # add menu item and report on errors
        addmenu_item_ctx = idaapi.add_menu_item(menupath, name, hotkey, flags, pyfunc, args)
        if addmenu_item_ctx is None:
            return 1
        else:
            self.addmenu_item_ctxs.append(addmenu_item_ctx)
            return 0

    def add_menu_items(self):

        if self.add_menu_item_helper("View/Open subviews/Problems", "Patches", "", 1, self.show_patches_view, None): return 1
        if self.add_menu_item_helper("Edit/Patch program/", "Edit selection...", "", 0, self.show_edit_form, None):  return 1
        if self.add_menu_item_helper("Edit/Patch program/", "Fill selection...", "", 0, self.show_fill_form, None):  return 1
        if self.add_menu_item_helper("Edit/Export data...", "Import data...", "Shift-I", 1, self.show_import_form, None):   return 1

        return 0

    def del_menu_items(self):
        for addmenu_item_ctx in self.addmenu_item_ctxs:
            idaapi.del_menu_item(addmenu_item_ctx)

    #--------------------------------------------------------------------------
    # View Callbacks
    #--------------------------------------------------------------------------   
    
    # Patches View
    def show_patches_view(self):
        self.patch_view.show()

    # Patches Edit Dialog
    def show_edit_form(self):
        selection, start_ea, end_ea = idaapi.read_selection()
        
        if not selection:
            start_ea = idaapi.get_screen_ea()
            end_ea = start_ea + 1

        buf_len = end_ea - start_ea
        buf = idaapi.get_many_bytes(start_ea, buf_len) or "\xFF"*buf_len
        buf_str = " ".join(["%02X" % ord(x) for x in buf])

        fpos = idaapi.get_fileregion_offset(start_ea)

        addr_str = "%#X" % start_ea
        fpos_str = "%#x" % fpos if fpos != -1 else "N/A" 

        f = PatchEditForm(addr_str, fpos_str, buf_str, buf_str)

        # Execute the form
        ok = f.Execute()
        if ok == 1:

            # Convert hex bytes to binary
            buf = f.strPatch.value
            buf = buf.replace(' ','')       # remove spaces
            buf = buf.replace('\\x','')     # remove '\x' prefixes
            buf = buf.replace('0x','')      # remove '0x' prefixes
            try:
                buf = binascii.unhexlify(buf)   # convert to bytes
            except Exception, e:
                idaapi.warning("Invalid input: %s" % e)
                f.Free()
                return

            # Now apply newly patched bytes
            idaapi.patch_many_bytes(start_ea, buf)

            # Refresh all IDA views
            self.patch_view.Refresh()

        # Dispose the form
        f.Free()

    # Fill range with a value form
    def show_fill_form(self):
        selection, start_ea, end_ea = idaapi.read_selection()
        
        if not selection:
            start_ea = idaapi.get_screen_ea()
            end_ea = start_ea + 1
        
        # Default fill value
        fill_value = 0x00

        # Create the form
        f = PatchFillForm(start_ea, end_ea, fill_value)

        # Execute the form
        ok = f.Execute()
        if ok == 1:

            # Get updated values
            start_ea = f.intStartEA.value
            end_ea = f.intEndEA.value
            fill_value = f.intPatch.value

            # Now apply newly patched bytes
            # NOTE: fill_value is expected to be one byte
            #       so if a user provides a larger patch_byte()
            #       will trim the value as expected.


            for ea in range(start_ea, end_ea):
                idaapi.patch_byte(ea, fill_value)

            # Refresh all IDA views
            self.patch_view.Refresh()

        # Dispose the form
        f.Free()

    # Import data form
    def show_import_form(self):
        selection, start_ea, end_ea = idaapi.read_selection()

        if not selection:
            start_ea = idaapi.get_screen_ea()
            end_ea = start_ea + 1

        # Create the form
        f = DataImportForm(start_ea, end_ea);

        # Execute the form
        ok = f.Execute()
        if ok == 1:

            start_ea = f.intStartEA.value
            end_ea = f.intEndEA.value

            if f.rFile.selected:
                imp_file = f.impFile.value

                try:
                    f_imp_file = open(imp_file,'rb')
                except Exception, e:
                    idaapi.warning("File I/O error({0}): {1}".format(e.errno, e.strerror))
                    return
                else:
                    buf = f_imp_file.read()
                    f_imp_file.close()

            else:

                buf = f.strPatch.value

                # Hex values, unlike string literal, needs additional processing
                if f.rHex.selected:
                    buf = buf.replace(' ','')       # remove spaces
                    buf = buf.replace('\\x','')     # remove '\x' prefixes
                    buf = buf.replace('0x','')      # remove '0x' prefixes
                    try:
                        buf = binascii.unhexlify(buf)   # convert to bytes
                    except Exception, e:
                        idaapi.warning("Invalid input: %s" % e)
                        f.Free()
                        return

            if not len(buf):
                idaapi.warning("There was nothing to import.")
                return

            # Trim to selection if needed:
            if f.cSize.checked:
                buf_size = end_ea - start_ea
                buf = buf[0:buf_size]

            # Now apply newly patched bytes
            idaapi.patch_many_bytes(start_ea, buf)

            # Refresh all IDA views
            self.patch_view.Refresh()

        # Dispose the form
        f.Free()
       
#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class idapatcher_t(plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = "Enhances manipulation and application of patched bytes."
    help = "Enhances manipulation and application of patched bytes."
    wanted_name = "IDA Patcher"
    wanted_hotkey = ""

    def init(self):  
        global idapatcher_manager

        # Check if already initialized
        if not 'idapatcher_manager' in globals():

            idapatcher_manager = PatchManager()
            if idapatcher_manager.add_menu_items():
                print "Failed to initialize IDA Patcher."
                idapatcher_manager.del_menu_items()
                del idapatcher_manager
                return idaapi.PLUGIN_SKIP
            else:  
                print("Initialized IDA Patcher  v%s (c) Peter Kacherginsky <iphelix@thesprawl.org>" % IDAPATCHER_VERSION)
            
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        global idapatcher_manager
        idapatcher_manager.show_patches_view()

    def term(self):
        pass
        

def PLUGIN_ENTRY():
    return idapatcher_t()

#--------------------------------------------------------------------------
# Script / Testing
#--------------------------------------------------------------------------
def idapatcher_main():
    global idapatcher_manager

    if 'idapatcher_manager' in globals():
        idapatcher_manager.del_menu_items()
        del idapatcher_manager

    idapatcher_manager = PatchManager()
    idapatcher_manager.add_menu_items()
    idapatcher_manager.show_patches_view()

if __name__ == '__main__':
    #idapatcher_main()
    pass