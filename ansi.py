import enum

class Color:

    Red = '\x1b[;31m'
    Green = '\x1b[;32m'
    Yellow = '\x1b[;33m'
    Blue = '\x1b[;34m'
    Magenta = '\x1b[;35m'
    Cyan = '\x1b[;36m'
    White = '\x1b[;37m'
    Default = '\x1b[;38m'
    Reset = '\x1b[;0m'

class Style:
    
    Underline = '\x1b[4m'
    Reset = '\x1b[0m'