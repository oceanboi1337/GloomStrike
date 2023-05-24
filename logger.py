import enum, ansi

class Level(enum.IntEnum):
    
    INFO = 1
    WARNING = 2
    ERROR = 3

class Logger:

    def __init__(self, verbose : Level) -> None:
        self.verbose = verbose

    def info(self, string):
        if self.verbose >= Level.INFO:
            print(f'{ansi.Color.Green}[INFO]: {string}{ansi.Color.Reset}')

    def warning(self, string):
        if self.verbose >= Level.WARNING:
            print(f'{ansi.Color.Yellow}[WARNING]: {string}{ansi.Color.Reset}')
    
    def error(self, string):
        if self.verbose >= Level.WARNING:
            print(f'{ansi.Color.Red}[ERROR]: {string}{ansi.Color.Reset}')