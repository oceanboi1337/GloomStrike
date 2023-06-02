import enum
from gloomstrike import ansi

class Level(enum.Enum):
    LOG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3

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

    if verbose < level.value:
        return

    print(f'{color}{head}: {style}{string}', end=end, flush=flush)
