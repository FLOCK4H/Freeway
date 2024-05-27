class ColorCodes:
    RED = "\033[31m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    RESET = "\033[0m"
    BRIGHT = "\033[1m"
    YELLOW = "\033[33m"
    MAGENTA = "\033[35m"
    LIGHT_GREEN = "\033[92m"
    LIGHT_BLUE = "\033[94m"
    LIGHT_CYAN = "\033[96m"
    LIGHT_RED = "\033[91m"
    LIGHT_MAGENTA = "\033[95m"
    LIGHT_YELLOW = "\033[93m"
    LIGHT_WHITE = "\033[97m"
    BLACK = "\033[30m"
    ORANGE = "\033[38;5;208m"
    PURPLE = "\033[38;5;93m"
    DARK_GRAY = "\033[38;5;238m"
    LIGHT_GRAY = "\033[38;5;245m"
    PINK = "\033[38;5;213m"
    BROWN = "\033[38;5;130m"
    BLINK = "\033[5m"

def cprint(string, color=ColorCodes.BLUE):
    print(f'{ColorCodes.RESET}{ColorCodes.CYAN}[+]{ColorCodes.RESET}' + ' ' + f'{ColorCodes.BRIGHT}{color}{string}{ColorCodes.RESET}')

def wprint(string):
    print(f'{ColorCodes.WHITE}[+]{ColorCodes.RESET}' + ' ' + f'{ColorCodes.RED}{string}{ColorCodes.RESET}')

def iprint(string):
    print(f'{ColorCodes.BRIGHT}{ColorCodes.GREEN}[{ColorCodes.RED}3WAY{ColorCodes.GREEN}]{ColorCodes.RESET}' + ' ' + f'{ColorCodes.WHITE}{ColorCodes.BRIGHT}{string}{ColorCodes.BRIGHT}{ColorCodes.RESET} ')

def oneline(string, sys, color=ColorCodes.GREEN):
    sys.stdout.write(f'\r{ColorCodes.GREEN}[{ColorCodes.RED}3WAY{ColorCodes.GREEN}]{ColorCodes.RESET}' + ' ' + f"{color}{ColorCodes.BRIGHT}{string}{ColorCodes.RESET}")
    sys.stdout.flush()

def cinput(string, color=ColorCodes.CYAN, b=False):
    r = input(f'{ColorCodes.GREEN}[>]{ColorCodes.RESET}' + ' ' + f'{color}{ColorCodes.BRIGHT if b else color}{string}:{ColorCodes.RESET} ')
    return r