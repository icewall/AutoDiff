from idc import *
from idautils import *
from idaapi import *
import sqlite3
import config
from logger import *

class SignificantFunctions(object):
    #necessary table creation
    tblCore = """CREATE TABLE sf_safeFunctions(
                 id integer primary key,
                 func_id integer,
                 primary_count integer,
                 secondary_count integer)
              """

    tblDebug = """
                CREATE TABLE sf_debug(
                 id integer primary key,
                 func_id integer,
                 file_id integer,
                 sig_id text)
               """

    tblSummary = """
                CREATE TABLE sf_summary(
                id integer primary key,
                func_id integer,
                sf_patch integer
                )
                 """
                
    safeFunctions = None
    
    def __init__(self):        
        self.safeFunctions = self._loadSafeFunctionsSignatures()

    def initialize(self,binDiffSQL,idbFlag):

        Logger.log("[SignificantFunctions] init")
        self._dbHandler = binDiffSQL.getDbHandler()
        self._binDiffSQL = binDiffSQL
        self._idbFlag = idbFlag

        #db creation is not necessary 
        if idbFlag == 2: return

        createTables = [SignificantFunctions.tblCore,SignificantFunctions.tblDebug,SignificantFunctions.tblSummary]
        delTables = ["sf_safeFunctions","sf_debug","sf_summary"]
        
        #DB operations
        self._binDiffSQL.dropTables(delTables)
        self._binDiffSQL.createTables(createTables)

    def rate(self,functions):               
        cur = self._dbHandler.cursor()
        functions = cur.execute("SELECT * from sf_safeFunctions").fetchall()
        for function in functions:
            if function["primary_count"] > function["secondary_count"]:
                #means there is security patch
                cur.execute("INSERT INTO sf_summary values(null,?,1)",(function["func_id"],))
        self._dbHandler.commit()
        cur.close()
    
    def preRate(self,functions):
        """
        Put ur code here if u wanna modify BinDiff DB or modify functions list
        """
        pass

    def collectInformations(self):
        Logger.log("SignificantFunctions : starts collecting info")
        self._safeFunctionsUsage(self._binDiffSQL.getFunctions())

    def _safeFunctionsUsage(self,functions):
        cur = self._dbHandler.cursor()
        for function in functions:
            counter = 0
            ea = function["address1"] if self._idbFlag == 1 else function["address2"]
            calls = self._getCalledFunctions(ea)
            if calls == None: continue            
            for call in calls.values():
                if call in self.safeFunctions:
                    counter += 1
                    Logger.log("Adding hit for %s with signature %s" % (hex(ea),call))
                    cur.execute("INSERT INTO sf_debug values(null,?,?,?)",(function["id"],self._idbFlag,call))
            
            if not counter: 
                continue 

            if self._idbFlag == 1:
                cur.execute("INSERT INTO sf_safeFunctions values(null,?,?,0)" , (function["id"],counter))
            else:
                cur.execute("UPDATE sf_safeFunctions SET secondary_count = ? WHERE func_id = ?" , (counter,function["id"]) )           

        self._dbHandler.commit()
        cur.close()

    def _loadSafeFunctionsSignatures(self):
        return [line.rstrip() for line in file(config.TMP_SIGS,'r')]

    def _getFunctionName(self,ea):
        name = GetFunctionName(ea)
        if name != "":            
            demangled_name = Demangle(name,GetLongPrm(INF_SHORT_DN))
            if demangled_name == None:
                return name #situation appears e.g for _memcpy
            return demangled_name[0:demangled_name.find("(")]    
        return "".join(re.findall("_([a-zA-Z\d]*)@",GetDisasm(ea)))


    def _getCalledFunctions(self,ea):
        f_start = ea
        f_end   = FindFuncEnd(f_start)
        calls = {}
        for head in Heads(f_start,f_end):
            if not isCode(GetFlags(head)):
                continue
            refs = CodeRefsFrom(head,0)
            refs = set(filter(lambda x: not (x>=f_start and x<=f_end), refs))    
            refs = [ref for ref in refs]
            if len(refs) > 0:
                calls[head] = self._getFunctionName(refs[0])
        return calls