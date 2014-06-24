from idc import *
from idautils import *
from idaapi import *
import sqlite3
import hashlib
import traceback

class Rematcher(object):
    
    tblInf = """
                CREATE TABLE rematcher_info(
                id integer PRIMARY KEY,
                address integer,
                hash text,
                file_id integer
                )
             """
    tblSummary = """
                    CREATE TABLE rematcher_summary(
                    id integer PRIMARY KEY,
                    address1 integer,
                    address2 integer,
                    old integer
                    )
                 """

    def __init__(self):
        pass
    
    def initialize(self,binDiffSQL,idbFlag):
        print "[ReMatcher] init"
        self._dbHandler = binDiffSQL.getDbHandler()
        self._binDiffSQL = binDiffSQL
        self._idbFlag = idbFlag
        if idbFlag == 2:
            return
        delTables = ["rematcher_info","rematcher_summary"]
        createTables = [Rematcher.tblInf,Rematcher.tblSummary]
        
        #DB operations        
        self._binDiffSQL.dropTables(delTables)
        self._binDiffSQL.createTables(createTables)

    def rate(self,functions):
        pass

    def preRate(self,functions):
        print "[ReMatcher] start preRate"        
        matchedfunc = ''
        alreadyMatched = []
        #get entries for primary idb
        functions1 = self._dbHandler.execute("SELECT * FROM rematcher_info WHERE file_id = 1").fetchall()
        for primary in functions1:
            try:
                match = self._dbHandler.execute("SELECT * from rematcher_info WHERE file_id = 2 AND hash = ?",(primary["hash"],)).fetchall()          
                if match != None and match != []:
                    if len(match) > 1:
                        print "Huh, more than one candidate to re-match"
                    match = match[0]
                    #remove already matched func
                    if match["address"] in alreadyMatched:
                        continue

                    func = filter(lambda row: row["address1"] == primary["address"],functions)
                    #remove found function from functions list and update db
                    func = func[0]
                    functions.remove(func)
                    #update db | !!!!! MAKE IT BETTER ??? !!!!!
                    #self._dbHandler.execute("UPDATE function SET address2 =?,similarity=2.0 WHERE address1=?",(match["address"],primary["address"]))
                    #print "There is new pair func1 : 0x%x   func2 : 0x%x  -> old : 0x%x" % (int(primary["address"]),int(match["address"]),int(func["address2"]))
                    #save this info to DB
                    self._dbHandler.execute("INSERT INTO rematcher_summary VALUES(null,?,?,?)",(primary["address"],match["address"],func["address2"]) )
                    #add to already matched/used list
                    alreadyMatched.append(match["address"])
                else:
                    #means that there is not function to re-match
                    pass # do nothing ?

            except sqlite3.Error as e:
                print "[BinDiffSQL] ", e.args[0]
                traceback.print_exc()

            self._dbHandler.commit()
    
    def collectInformations(self):
        print "ReMatcher : starts collecting info"
        functions = self._binDiffSQL.getFunctions()      
           
        for func in functions:
            ea = func["address1"] if self._idbFlag == 1 else func["address2"]
            data = ''
            f = get_func(ea)
           
            #if f == None: continue ,,,,this code triggers some strange exception in idaapi
            if not hasattr(f,"startEA"): continue
            cur_addr = f.startEA
            while cur_addr != 0 and cur_addr < f.endEA:            
                data += GetMnem(cur_addr)
                op1 = GetOpType(cur_addr, 0)
                op2 = GetOpType(cur_addr, 1)
                if op1 != 0 and op1 != 2 and op1 != 6 and op1 != 7:
                    data += GetOpnd(cur_addr, 0)
                if op2 != 0 and op2 != 2 and op2 != 6 and op2 != 7:
                    data += GetOpnd(cur_addr, 1)
            
                cur_addr = FindCode(cur_addr, SEARCH_DOWN | SEARCH_NEXT)

            #save it to db
            self._dbHandler.execute("INSERT INTO rematcher_info values(null,?,?,?)",
                                    (ea,hashlib.sha1(data).hexdigest(),self._idbFlag)
                                    )

            del data

        self._dbHandler.commit()