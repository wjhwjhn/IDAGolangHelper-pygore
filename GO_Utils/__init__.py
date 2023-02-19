import idaapi
from . import Utils
from . import Firstmoduledata
from . import Types
from . import GoStrings
import idc
import idautils
import pygore
import ida_ida
import ida_funcs
import ida_bytes


class GoSettings(object):

    def __init__(self):
        self.storage = {}
        self.bt_obj = Utils.get_bitness(ida_ida.inf_get_min_ea())
        self.structCreator = Utils.StructCreator(self.bt_obj)
        self.processor = None
        self.typer = None
        self.binaryPath = idaapi.get_input_file_path()
        self.structsDef = {}

    def getVal(self, key):
        if key in self.storage:
            return self.storage[key]
        return None

    def setVal(self, key, val):
        self.storage[key] = val

    def tryFindGoVersion(self):
        f = pygore.GoFile(self.binaryPath)
        v = f.get_compiler_version()
        f.close()
        return "Go Compiler Version should be %s" % (v.name)

    def renameFunctions(self):
        f = pygore.GoFile(self.binaryPath)
        c = f.get_compiler_version()
        print('Compiler: {}\nTimestamp: {}\nSHA {}\n'.format(c.name, c.timestamp, c.sha))
        pkgs = f.get_packages()
        vendor_pkgs = f.get_vendor_packages()
        unknown_pkgs = f.get_unknown_packages()
        std_pkgs = f.get_std_lib_packages()
        for p in pkgs:
            Utils.pkgs_work(p)
        for p in vendor_pkgs:
            Utils.pkgs_work(p)
        for p in unknown_pkgs:
            Utils.pkgs_work(p)
        for p in std_pkgs:
            Utils.pkgs_work(p)

    def _getStructDef(self, t):
        print(t.kind, t.fields)
        if t.kind == pygore.Kind.Struct and t.fields:
            buf = "type %s struct{" % t.name
            for f in t.fields:
                if f.fieldAnon:
                    buf += "\n\t%s" % f
                else:
                    buf += "\n\t%s %s" % (f.fieldName, f.name)
            if len(t.fields) > 0:
                buf += "\n"
            return buf + "}"
        else:
            return ""

    def renameStructs(self):
        f = pygore.GoFile(self.binaryPath)
        # print(f)
        # print(self.binaryPath)
        c = f.get_compiler_version()
        print('Compiler: {}\nTimestamp: {}\nSHA {}\n'.format(c.name, c.timestamp, c.sha))

        # pkgs = f.get_packages()
        types = f.get_types()
        f.close()
        for t in types:
            name = Utils.relaxName(t.name)
            Utils.rename(t.addr, name)
            struct_data = self._getStructDef(t)
            if struct_data != "":
                print(struct_data)
                self.structsDef[t.addr] = struct_data
            # print(hex(t.addr), name)

    def getStructDefByCursor(self):
        addr = idc.get_operand_value(idc.here(), 1)
        print(self.structsDef[addr])

    def createTyper(self, typ):
        if typ == 0:
            self.typer = Types.Go12Types(self.structCreator)
        elif typ == 1:
            self.typer = Types.Go14Types(self.structCreator)
        elif typ == 2:
            self.typer = Types.Go15Types(self.structCreator)
        elif typ == 3:
            self.typer = Types.Go16Types(self.structCreator)
        elif typ == 4 or typ == 5:
            self.typer = Types.Go17Types(self.structCreator)
        elif typ == 6:  # 1.9
            self.typer = Types.Go17Types(self.structCreator)
        elif typ == 7:  # 1.10
            self.typer = Types.Go17Types(self.structCreator)

    def typesModuleData(self, typ):
        if typ < 2:
            return
        if self.getVal("firstModData") is None:
            self.findModuleData()
        fmd = self.getVal("firstModData")
        if fmd is None:
            return
        if self.typer is None:
            self.createTyper(typ)
        robase = None
        if typ == 4:
            beg, end, robase = Firstmoduledata.getTypeinfo17(fmd, self.bt_obj)
            self.processor = Types.TypeProcessing17(beg, end, self.bt_obj, self, robase)
        elif typ == 5:
            beg, end, robase = Firstmoduledata.getTypeinfo18(fmd, self.bt_obj)
            self.processor = Types.TypeProcessing17(beg, end, self.bt_obj, self, robase)
        elif typ == 6:
            beg, end, robase = Firstmoduledata.getTypeinfo18(fmd, self.bt_obj)
            self.processor = Types.TypeProcessing19(beg, end, self.bt_obj, self, robase)
        elif typ == 7:
            beg, end, robase = Firstmoduledata.getTypeinfo18(fmd, self.bt_obj)
            self.processor = Types.TypeProcessing19(beg, end, self.bt_obj, self, robase)
        else:
            beg, end = Firstmoduledata.getTypeinfo(fmd, self.bt_obj)
            self.processor = Types.TypeProcessing(beg, end, self.bt_obj, self)
        print("%x %x %x" % (beg, end, robase))
        for i in self.processor:
            pass
        return
