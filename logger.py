class Logger(object):

    """
        Available logging modes
    """
    NONE    = -1
    CONSOLE =  0
    FILE    =  1
    BOTH    =  2

    def __init__(self):
        pass

    @classmethod
    def init(cls):

        cls.__handlers = {cls.NONE    : cls.__noneHandler,
                          cls.CONSOLE : cls.__consoleHandler}

        cls.__handler = cls.__handlers[cls.NONE]
        pass
        
    @classmethod
    def log(cls,msg):
        cls.__handler(msg)
        pass

    """
    Handlers
    """
    @classmethod
    def __noneHandler(cls,msg):
        pass

    @classmethod
    def __consoleHandler(cls,msg):
        print msg

    @classmethod
    def setLoggerType(cls,type):
        cls.__handler = cls.__handlers[type]