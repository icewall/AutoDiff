from idc import *
from idaapi import *
from idautils import *
import sqlite3

class Sanitizer(object):

    tblDiffInstr = """
    CREATE TABLE diff_instr(
    id integer primary key,
    func_id integer,
    address1 integer default 0,
    address2 integer default 0,
    asm text,
    mnem text);
    """

    tblMeaninglessInstr = """
    CREATE TABLE sanitizer_summary(
    id integer primary key,
    func_id integer,
    meaningless_instr integer
    )
    """
        
    tblInstructionCount = """
                        CREATE TABLE instr_count(
                        id integer primary key,
                        func_id integer,
                        primary_count integer default 0,
                        secondary_count integer default 0)
                        """
    _idbFlag = None

    meaningLessInstr = set(['int','nop','ret','retn'])
                            
    def __init__(self):

        self._columns = {1: "primary_count",
                         2: "secondary_count"}
 
    def initialize(self,binDiffSQL,idbFlag):

        print "[Sanitizer] init"
        self._dbHandler = binDiffSQL.getDbHandler()
        self._idbFlag = idbFlag
        self._binDiffSQL = binDiffSQL
        self._blocks = set()

        #just don't do it for secondary DB...need to update database not delete it!!!
        if idbFlag == 2:  return

        createTables = [Sanitizer.tblDiffInstr,
                        Sanitizer.tblInstructionCount,
                        Sanitizer.tblMeaninglessInstr]

        delTables = ["diff_instr","meaningless_instr","instr_count","sanitizer_summary"]

        #DB operations
        self._binDiffSQL.dropTables(delTables)
        self._binDiffSQL.createTables(createTables)

    def setIDBFlag(self,idbFlag):
        self._idbFlag = idbFlag

    def collectInformations(self):
        print "Sanitizer : starts collecting info"

        cur = self._dbHandler.cursor()
       
        for func in Functions():            
            self._countInstr(func,cur)

        functions = self._binDiffSQL.getFunctions()         
        for func in functions:       
            self._findDiffInstructions(func,cur)
                                                        
        self._dbHandler.commit()
        cur.close()
        
    def _countInstr(self,func,cur):

            f = FlowChart(get_func(func))
            funcRange = get_func(func)
            self._blocks = set()
            instr_count  = 0

   
            row = cur.execute("SELECT id,address1,address2 FROM function WHERE address%d = %d" % (self._idbFlag,funcRange.startEA)).fetchone()
            if row == None:
                #print "Looks like there is some problem with func at addre : 0x%x" % funcRange.startEA
                return

            #count instructions
            for block in f:
                instr_count += self._countInstrInternal(block.startEA,block.endEA,block.id)
                #for sucess BBs
                for succ_block in block.succs():
                    instr_count += self._countInstrInternal(block.startEA,block.endEA,block.id)
                for pred_block in block.preds():
                    instr_count += self._countInstrInternal(block.startEA,block.endEA,block.id)
              
            #print "Function 0x%x : has %d instructions" % (funcRange.startEA,instr_count)
            #update database
            if self._idbFlag == 1:                
                cur.execute("INSERT INTO instr_count values(null,%d,%d,0)" % (row["id"],instr_count))
            else:
                cur.execute("UPDATE instr_count SET secondary_count = %d WHERE func_id = %d" % (instr_count,row["id"]))
    
    def _countInstrInternal(self,start,end,id):
        if id not in self._blocks:
            self._blocks.add(id)
        else:
            return 0
        #count instructions
        c = 0
        for head in Heads(start,end):
            c +=1
        return c

    def _findDiffInstructions(self,func,cur):

        ea = func["address1"] if self._idbFlag == 1 else func["address2"]
        f = get_func(ea)

        try:
            row = cur.execute("SELECT id,address1,address2 FROM function WHERE address%d = %d" % (self._idbFlag,f.startEA)).fetchone()
            if row == None: return
            instructions = cur.execute("""
                                        select i.address%d
                                        from instruction as i
                                        join basicblock as b on i.basicblockid = b.id
                                        join function as f on f.id = b.functionid
                                        """ % self._idbFlag).fetchall()
        except:
            return

        instructions = map(lambda instr: instr[0],instructions)

        for head in Heads(f.startEA,f.endEA):
            if head in instructions or GetMnem(head) == "":
                continue

            #instr without match...add it to db
            #print "Adding diff instr at: 0x%x : %s" % (head,GetDisasm(head))
            if self._idbFlag == 1:                
                cur.execute("INSERT INTO diff_instr values(null,?,?,null,?,?)" , (row["id"],head,GetDisasm(head),GetMnem(head)) )
            else:
                cur.execute("INSERT INTO diff_instr values(null,?,null,?,?,?)" , (row["id"],head,GetDisasm(head),GetMnem(head)) )
    
    def rate(self,functions):             
        cur = self._dbHandler.cursor()
        status = {}
        for function in functions:
            added_instructions   = cur.execute("SELECT * FROM diff_instr WHERE func_id = ? AND coalesce(address2,0) = 0" ,(function["id"],)).fetchall()
            removed_instructions = cur.execute("SELECT * FROM diff_instr WHERE func_id = ? AND coalesce(address1,0) = 0" ,(function["id"],)).fetchall()

            self._meaninglessInstrDetection(cur,function,added_instructions,removed_instructions)
        
        self._dbHandler.commit()    
        cur.close()

    def preRate(self,functions):
        """
        Put ur code here if u wanna modify BinDiff DB or modify functions list
        """
        pass
    
    def _meaninglessInstrDetection(self,cur,function,added_instr,removed_instr):
        #convert list to set
        s_added_instr   = set(map(lambda instr: instr['mnem'],added_instr))
        s_removed_instr = set(map(lambda instr: instr['mnem'],removed_instr))
        a = (s_added_instr.issubset(Sanitizer.meaningLessInstr)  and len(s_added_instr) > 0 )
        b = (s_removed_instr.issubset(Sanitizer.meaningLessInstr) and len(s_removed_instr) > 0)
        c = (s_added_instr == s_removed_instr)
        if a: print "Added instructions set includes in removed instr set"
        if b: print "Removed instructions set includes in added instr set"
        if c: 
            print "Sets of mnemonics are equal"
            print "Number of mnemonics"
            print "Added : %d Removed : %d" % (len(s_added_instr),len(s_removed_instr))
        
        if  a or b or c:
            print "Meaningless instruction change detected: function id %d : address : 0x%x" % (function["id"],function["address1"])            
            #print "Instruction added: \n","\n".join(map(lambda instr: instr["asm"],added_instr))
            #print "Instruction removed: \n","\n".join(map(lambda instr: instr["asm"],removed_instr))
            row = cur.execute("SELECT * FROM sanitizer_summary WHERE func_id = ?",( function["id"],)).fetchone()
            if row == None:
                #no record for this function for this moment...just insert new one
                cur.execute("INSERT INTO sanitizer_summary values(null,?,1)",(function["id"],))
            else:
                cur.execute("UPDATE sanitizer_summary set meaningless_instr = 1 WHERE func_id = ?" ,(function["id"],) )
    
    def _unc_jmp_detection(self):
        pass
    
    def _miss_match_detection(self):
        """
            Detect that situation where BinDiff compared wrongly different functions. Try to find proper pair for it.
        """
        pass
    
