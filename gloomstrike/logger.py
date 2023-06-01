import enum
from gloomstrike import ansi

class Level(enum.Enum):
    LOG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4

verbose = 0

def log(string: str, style: str='', end: str='\n', flush: bool = True, level: Level = Level.LOG):

    color = ansi.Color.Blue
    head = f'[{level.name}]'

    match level:
        case Level.INFO:
            color = ansi.Color.Green
        case Level.WARNING:
            color = ansi.Color.Yellow
        case Level.ERROR:
            color = ansi.Color.Red

    print(f'{color}{head}: {style}{string}', end=end, flush=flush)
