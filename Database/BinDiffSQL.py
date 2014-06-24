import sqlite3
import os

class BinDiffSQL(object):       
    _dbPath = None
    _dbHandler = None
    
    def __init__(self,diffPath):
        self._dbPath = diffPath
        #open database
        #TODO maybe there is easier way ?
        print "Diff path : %s" % diffPath
        if not os.path.isfile(diffPath):
            raise IOError('BinDiff db could not be found')

        self._dbHandler = sqlite3.connect(self._dbPath)
        self._dbHandler.row_factory = sqlite3.Row
    
    def getFunctions(self):
        return self._dbHandler.execute("select * from function where similarity < 1.0 order by similarity").fetchall()

    def updateFunctions(self,functions):
        pass
    
    def getDbHandler(self):
        return self._dbHandler
    
    def getDbPath(self):
        return self._dbPath

    def createTables(self,tables):
        for table in tables:
            try:
                self._dbHandler.execute(table)
            except sqlite3.Error as e:
                print "An error occurred:", e.args[0]
        self._dbHandler.commit()
    
    def dropTables(self,tables):
        for table in tables:
            try:
                self._dbHandler.execute("DROP TABLE %s" % table)
            except sqlite3.Error as e:
                print "An error occurred:", e.args[0]
        self._dbHandler.commit() 
