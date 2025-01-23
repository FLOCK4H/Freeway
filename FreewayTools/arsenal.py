import os

try:
    from FreewayTools.colors import cprint, wprint, cinput, ColorCodes

except ModuleNotFoundError:
    from colors import cprint, wprint, cinput, ColorCodes

def create_arsenal_storage(path):
    if os.path.exists(path):
        return 
    
    try:
        with open(path, 'w') as f:
            f.write('')
    except Exception as e:
        wprint(e)

class ArsenalAdd:
    def __init__(self, arsenal: str = ""):
        self.arsenal = arsenal
        create_arsenal_storage('/usr/local/share/3way/arsenal')
        self.add_to_arsenal_storage(arsenal)

    def add_to_arsenal_storage(self, weapon):
        try:
            with open('/usr/local/share/3way/arsenal', 'a') as f:
                f.write(weapon + '\n')
            cprint("Tool added!")
        except Exception as e:
            wprint("Something went wrong when adding the tool!", str(e))

class ArsenalCheck:
    def __init__(self):
        self.arsenal = []
        create_arsenal_storage('/usr/local/share/3way/arsenal')
        self.check_arsenal_storage()

    def check_arsenal_storage(self):
        try:
            with open("/usr/local/share/3way/arsenal", "r") as f:
                self.arsenal = f.read().split("\n")
        except Exception as e:
            wprint(f"Something went wrong when checking the arsenal: {str(e)}")

class ArsenalRem:
    def __init__(self, arsenal: str = ""):
        self.weapon_found = False
        self.arsenal = arsenal
        create_arsenal_storage('/usr/local/share/3way/arsenal')
        self.remove_from_arsenal_storage(arsenal)

    def remove_from_arsenal_storage(self, weapon):
        try:
            with open('/usr/local/share/3way/arsenal', 'r') as f:
                lines = f.readlines()

            for line in lines:
                if weapon in line:
                    self.weapon_found = True
                
            if not self.weapon_found:
                wprint("The tool you are trying to remove is not in the arsenal!")
                return

            with open('/usr/local/share/3way/arsenal', 'w') as f:
                for line in lines:
                    if line.find(" ") != -1:
                        line = line.split(" ")[1]
                        if line.strip("\n") != weapon:
                            f.write(line)
            cprint("Tool removed!")
        except Exception as e:
            wprint(f"Something went wrong when removing the tool: {str(e)}")