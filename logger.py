import enum, ansi

class Level(enum.IntEnum):
    
    INFO = 1
    WARNING = 2
    ERROR = 3

class Logger:

    def __init__(self, verbose : Level) -> None:
        self.verbose = verbose

    def info(self, string, esc : str='', newline : bool=True):
        if self.verbose >= Level.INFO:
            print(f'{esc}{ansi.Color.Green}[INFO]: {string}{ansi.Color.Reset}', end='\n' if newline else '')

    def warning(self, string, esc : str='', newline : bool=True):
        if self.verbose >= Level.WARNING:
            print(f'{esc}{ansi.Color.Yellow}[WARNING]: {string}{ansi.Color.Reset}', end='\n' if newline else '')
    
    def error(self, string, esc : str='', newline : bool=True):
        if self.verbose >= Level.WARNING:
            print(f'{esc}{ansi.Color.Red}[ERROR]: {string}{ansi.Color.Reset}', end='\n' if newline else '')