try:
    from idc import *
    from idautils import *
    from idaapi import *
except ImportError:
    print "Problem with module importing"

from logger import *
Logger.init(Logger.FILE)
Logger.log("start logging...")

try:
    import ptvsd
    ptvsd.enable_attach(None)
except Exception as e:
    Logger.log(e.message)

import Database.BinDiffSQL as db
idaapi.require("Database.BinDiffSQL")

import sys
import os
import shutil
import sqlite3
import subprocess
import getopt
import config
import traceback
from BinDiffFilter import *


"""
MODULES
"""
import Modules.SignificantFunctions.SignificantFunctions as sf
import Modules.Sanitizer.Sanitizer as sanitizer
import Modules.Rematcher.Rematcher as rematcher
idaapi.require("Modules.SignificantFunctions.SignificantFunctions")
idaapi.require("Modules.Sanitizer.Sanitizer")
idaapi.require("Modules.Rematcher.Rematcher")


class AutoDiffSummaryForm(Choose2):
    def __init__(self,title):
        Choose2.__init__(self,title,[ ["similarity",10],
                                     ["EA primary",10],
                                     ["EA secondary",10],
                                     ["instructions primary",10] ,
                                     ["instructions secondary",10],
                                     ["sanitizer_summary",10],
                                     ["safeFunctions_summary",10]                                     
                                     ],embedded=False,width=30, height=20)        
        self.n = 0
        self.icon = 5
        self.selcount = 0
    
    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n


class CAutoDiff(object):

    def _setFields(self):
        self._binDiffSQL = None
        self._diffPath = None
        self._inIDA = False
        self._modules = None
        self._instances = None
        self._idbFlag = None
        self._secondIDB = None
        self.__IDA_PATH = ""
        self.BinDiffFilter = CBinDiffFilter()

    def __init__(self,args):
        self._setFields()

        self._optMethods = {
                            "-f"       : self._setFileID,
                            "-b"       : self._setBinDiffDB,
                            "-d"       : self._setSecondIDB,
                            "-a"       : self._batchMode,
                            "-c"       : self._collectInformations,
                            "-r"       : self._rate,
                            "-s"       : self._getSummary
                            }
        #Create BinDiff database object handler
        
        self._modules = [sanitizer.Sanitizer,
                         sf.SignificantFunctions,
                         rematcher.Rematcher]
        self._instances = []
        #initialize modules
        for module in self._modules:
            self._instances.append(module())
                    
        #choose2 init
        self._summaryForm = AutoDiffSummaryForm("AutoDiff - Summary")
        #PARSE ARGV
        self._parseArgs(args)

    def _parseArgs(self,args):
        try:
            Logger.log("[AutoDiff] parsing args")
            batchFlag = False        
            if len(args) == 1:
                return        
            #means it's batch mode and Exit should be called at the end   
            #ptvsd.wait_for_attach()                           
            optlist,args = getopt.getopt(args,"h:f:b:d:crsa")        
            Logger.log(repr(optlist))        
            for o,p in optlist:
                self._optMethods[o](p)
                batchFlag = True
        except Exception as e:
            Logger.log(e.message)
            Logger.log(traceback.print_exc())

        if batchFlag:
            Exit(0)
            pass

    #####
    ##  Option methods
    ###

    def _setFileID(self,fileID):
        self._idbFlag = int(fileID)

    def _setBinDiffDB(self,diffPath):
        Logger.log("_setBinDiffDB")
        self._diffPath = diffPath
    
    def _setSecondIDB(self,secondIDB):
        self._secondIDB = secondIDB
        self._setArch(secondIDB)        
                               
    def _batchMode(self,nop):
        #3 steps
        self._collectInformations()
        self._rate()
        self._getSummary()


    #####
    ##  END of Options methods
    ###
        
    def _emptyMenu(self):
        pass
    
    def init(self):
        self._initDB()                
        if self._idbFlag == None:
            self._idbFlag = idaapi.asklong(1,"Which IDB u handle right now ?(1 = primary,2 = secondary)")        
        for module in self._instances:
            Logger.log("calling init method")
            module.initialize(self._binDiffSQL,self._idbFlag)

    def _collectInformations(self, nop = 0):
        self.init()        
        for module in self._instances:
            module.collectInformations()
        Logger.log("[+]AutoDiff - Informations collected")
        if self._idbFlag == 2:
            Logger.log("Exiting because it's second IDB")
            return
                
        Logger.log("[+]AutoDiff - Time for second IDB")
        
        if config.DEBUG:
            self._secondIDB = config.SECOND_IDB
        elif self._secondIDB == None:
            self._secondIDB = idaapi.askfile_c(0,"*.idb","Point Second IDB file")        
        subprocess.call('%s -A -S"%s %s" %s' % (self.__IDA_PATH,config.AUTODIFF,('-f 2 -b \\"%s\\" -c') % self._diffPath,self._secondIDB) ,shell=True)
        Logger.log("[+]AutoDiff - data collected")
    
    def _summarize(self):
        #show summary
        self._initDB()        
        self._summaryForm.items = self._getSummary()
        self._summaryForm.Show()
        return
        
    def _rate(self,nop = 0):
        self._initDB()
        functions = self._binDiffSQL.getFunctions()
        #pre-rate for modules which modify bindiffDB,,,e.g
        for module in self._instances:
            module.preRate(functions) #functions list can be modified in this method!!!

        for module in self._instances:
            module.rate(functions)
        Logger.log("[+]AutoDiff - Functions have been rated")

    def registerMenus(self):
           idaapi.add_menu_item("Edit/Plugins/", "-", None, 0, self._emptyMenu, ())
           idaapi.add_menu_item("Edit/Plugins/", "AutoDiff: Summarize 2.0", "", 0, self._filterBinDiffWindow, ())           
           idaapi.add_menu_item("Edit/Plugins/", "AutoDiff: Generate AutoDiff'ed BinDiff database", "", 0, self._generateDatabase, ())           
           idaapi.add_menu_item("Edit/Plugins/", "AutoDiff: Summarize", "", 0, self._summarize, ())           
           idaapi.add_menu_item("Edit/Plugins/", "AutoDiff: Rate informations", "", 0, self._rate, ())
           idaapi.add_menu_item("Edit/Plugins/", "AutoDiff: Collect informations", "", 0, self._collectInformations, ())
    
    def _initDB(self):
        if self._binDiffSQL == None:
            #DEBUG!!!!
            if config.DEBUG:
                self._diffPath = config.BINDIFF
            if self._diffPath == None:                
                self._diffPath = idaapi.askfile_c(0,"*.BinDiff","Point BinDiff database file")
            self._binDiffSQL = db.BinDiffSQL(self._diffPath)
    
    def _getSummary(self,nop = 0):
        sqlQuery = """
                    SELECT f.similarity,f.address1,f.address2,coalesce(i.primary_count,0),coalesce(i.secondary_count,0),coalesce(sa.meaningless_instr,0),coalesce(sf.sf_patch,0)
                    FROM function as f
                    LEFT JOIN instr_count as i ON i.func_id = f.id
                    LEFT JOIN sanitizer_summary as sa ON sa.func_id = f.id
                    LEFT JOIN sf_summary as sf ON sf.func_id = f.id
                    WHERE f.similarity < 1.0                    
                   """
        cur = self._binDiffSQL.getDbHandler().cursor()
        
        try:
            rows = cur.execute(sqlQuery).fetchall()
        except sqlite3.Error as e:
            print "An error occurred:", e.args[0]

        data = [list(str(e) for e in list(row)) for row in rows]        
        self._printSummary(cur,len(data))
        cur.close()
        return self._correctFormat(data)

    def _printSummary(self,cur,functionsCount):
        functionsCount = int(functionsCount)
        sqlSanitizedFunctions = """
                        SELECT count(*)
                        FROM function as f 
                        WHERE similarity < 1.0 AND f.id IN (SELECT func_id FROM sanitizer_summary)
                      """
        sqlSafeIntCount = """
                            SELECT count(*) FROM sf_summary
                          """
        sqlReMatched = """
                        SELECT count(*) FROM rematcher_summary
                       """
                        
        row = cur.execute(sqlSanitizedFunctions).fetchone()
        sanitizedFunctionsCount = int(row[0])
        row = cur.execute(sqlSafeIntCount).fetchone()
        safeIntCount = int(row[0])
        row  = cur.execute(sqlReMatched).fetchone()
        reMatchedCount = int(row[0])
        #if it's batch mode log this info to separate file
        if self._batchMode:
            Logger.setLogFile("summary.txt")

        Logger.log("=======================================================")
        Logger.log("=                AutoDiff / Statistics                =")
        Logger.log("=======================================================")
        Logger.log("Number of changed functions declared by BinDiff : %d" % functionsCount)
        Logger.log("Number of functions filtered out by Sanitizer   : %d" % sanitizedFunctionsCount)
        Logger.log("Number of functions contain \"IntSafe patch\"   : %d" % safeIntCount)
        Logger.log("Number of functions ReMatched                   : %d" % reMatchedCount)
        Logger.log("Number of functions still left to analysis      : %d" % (functionsCount - (sanitizedFunctionsCount + safeIntCount + reMatchedCount)) )

    def _generateDatabase(self):
        self._initDB()
        dbPath = self._binDiffSQL.getDbPath()
        dirPath,fileName = os.path.split(dbPath)
        fileName = "AutoDiff_" + fileName
        autoDiffDBPath = os.path.join(dirPath,fileName)
        shutil.copy(dbPath,autoDiffDBPath)
        #connect to new database
        db = sqlite3.connect(autoDiffDBPath)
        db.row_factory = sqlite3.Row
        #remove unnecessary stuff
        db.execute("DELETE FROM function WHERE similarity >= 1.0 OR id IN (SELECT func_id FROM sanitizer_summary)")
        db.commit()
        db.close()
        Logger.log("AutoDiff'ed BinDiff database is ready to load!!!")
        Logger.log("FILE : %s" % autoDiffDBPath)
    
    def _filterBinDiffWindow(self):
        self._initDB()
        if not self.BinDiffFilter.findBinDiffWindow():
            return
        sqlInfSafeFunctions = """
                              SELECT address1 FROM function AS f 
                              JOIN sf_summary AS sf ON f.id = sf.func_id
                              """
        sqlReMatched        = """
                               SELECT address1 FROM rematcher_summary
                              """
        sqlSanitized        = """
                              SELECT address1 FROM function AS f 
                              JOIN sanitizer_summary AS s ON f.id = s.func_id                                
                              """
                
        handler = self._binDiffSQL.getDbHandler()
        #let's filter out some things
        self.BinDiffFilter.hideSomeStandardColumns()
        self.BinDiffFilter.proxy_model.hideMatchedFunctions()

        #easy to notice....rollup this code!!!
        #IntSafe marker
        IntSafeFunctions = handler.execute(sqlInfSafeFunctions).fetchall()
        for row in IntSafeFunctions:
            self.BinDiffFilter.addIntSafeFunction("%X" % row["address1"])

        #hide rematched functions cos they should have 1.0 similarity
        reMatched = handler.execute(sqlReMatched).fetchall()
        for row in reMatched:
            self.BinDiffFilter.proxy_model.hideFunction("%X" % row["address1"],False)
        
        sanitized = handler.execute(sqlSanitized).fetchall()
        for row in sanitized:
            self.BinDiffFilter.proxy_model.hideFunction("%X" % row["address1"],False)

        self.BinDiffFilter.proxy_model.invalidate() #for optymization purpose        
                

    """
        Helpers
    """

    def _correctFormat(self,data):
        for i in range(0,len(data)):
            row = data[i]
            #correct similarity
            row[0] = str(round(float(row[0]),2)) # yeyeye what a nice cast ;)
            #correct address1
            row[1] = str( hex( int(row[1]) ) )
            #correct address2
            row[2] = str( hex( int(row[2]) ) )
            data[i] = row

        return data           
    
    def _setArch(self,idbPath):
        path,ext = os.path.splitext(idbPath)
        if ext == ".i64": #PE+ (x64)
            self.__IDA_PATH = config.IDA.replace("idaq.exe","idaq64.exe")
        else:
            #PE (x86)
            self.__IDA_PATH = config.IDA
            

if __name__ == "__main__":
    print "Welcome in AutoDiff!!!"
    Logger.log("MAIN")
    AutoDiff = CAutoDiff(ARGV[1:])
    AutoDiff.registerMenus()