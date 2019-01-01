# GLOBAL VARIABLES
programName = ""
startAddress = ""
lctr = ""
prime = 301
baseAddress = ""


# INSTRUCTION CLASS
class Ins:
    label = ""
    opcode = ""
    operand = ""
    comment = ""
    hexOpcode = ""
    byteSize = 0
    address = ""
    hasLabel = False
    hasOpcode = False
    hasOperand = False
    hasComment = False
    PC = ""
    objectCode = ""
    N = False
    I = False
    X = False
    B = False
    P = True
    E = False

    # Constructor

    def __init__(self, string):
        global programName
        global startAddress
        global lctr

        if len(string) > 1:
            self.label = string[0]
            self.opcode = string[1]

            if string[1] == "START":

                programName = string[0]
                self.label = string[0]
                self.opcode = string[1]
                self.operand = string[2]
                startAddress = string[2]
                lctr = int(string[2], 16)
                self.hasLabel = True
                self.hasOperand = True
                self.hasOpCode = True
            elif len(string) == 4:
                self.label = string[0]
                self.opcode = string[1]
                self.operand = string[2]
                self.comment = string[3]
                self.hasLabel = True
                self.hasOpCode = True
                self.hasOperand = True
                self.hasComment = True
            elif len(string) == 3:
                self.label = string[0]
                self.opcode = string[1]
                self.operand = string[2]
                self.hasLabel = True
                self.hasOpCode = True
                self.hasOperand = True
            elif len(string) == 2:
                self.label = ""
                self.opcode = string[0]
                self.operand = string[1]
                self.hasOpCode = True
                self.hasOperand = True
            elif len(string) == 1:
                self.opcode = string[0]
        elif len(string) == 1:
            self.opcode = string[0]

    def printer(self):
        print("{:>10} {:>10} {:>10} {:>10}".format(hex(self.address), self.label, self.opcode, self.operand))

    def set_ByteSize(self, bs):
        self.byteSize = bs

    def set_hexOpcode(self, opcode):
        self.hexOpcode = opcode

    def set_Address(self, adrs):
        self.address = adrs

    def set_N(self, var):
        self.N = var

    def set_I(self, var):
        self.I = var

    def set_X(self, var):
        self.X = var

    def set_B(self, var):
        self.B = var

    def set_P(self, var):
        self.P = var

    def set_E(self, var):
        self.E = var

    def get_N(self):
        return self.N

    def get_I(self):
        return self.I


# FOR EACH LINE OF SICOPS FILE

class Operations:
    mnem = ""
    opcode = ""
    byteSize = ""
    register = ""

    def __init__(self, string):
        if len(string) == 4:
            self.mnem = string[0]
            self.opcode = string[1]
            self.byteSize = string[2]
        elif len(string) == 3:
            self.mnem = string[0]
            self.opcode = string[1]
            self.byteSize = string[2]
        elif len(string) == 2:
            self.register = string[0]
            self.opcode = string[1]


class HashTable:
    hashArray = []

    def __init__(self):
        self.hashArray = [None] * 301

    def put(self, hv, line):
        if self.hashArray[hv] is None:
            self.hashArray[hv] = line
            probe = -1
        else:
            if hv == len(self.hashArray):
                probe = 0
            else:
                probe = hv + 1
        while probe != -1 and probe != hashValue:
            if self.hashArray[probe] is None:
                self.hashArray[probe] = line
                probe = -1
            else:
                if probe == len(self.hashArray):
                    probe = 0
                else:
                    probe += 1

    def searchByteSize(self, hashValue, string):  # String will be the opcode
        while self.hashArray[hashValue] is not None:
            z = self.hashArray[hashValue]
            str = z.split()
            op = Operations(str)
            if op.mnem.strip() == string.strip():
                return op.byteSize
            else:
                hashValue = hashValue + 1 % prime

    def searchNumOpcode(self, hashValue, string):  # String will be the opcode
        while self.hashArray[hashValue] is not None:
            z = self.hashArray[hashValue]
            str = z.split()
            op = Operations(str)
            if op.mnem.strip() == string.strip():
                return op.opcode
            else:
                hashValue = hashValue + 1 % prime

    def searchAddressofLbl(self, hashValue, string):
        while self.hashArray[hashValue] is not None:
            z = self.hashArray[hashValue]
            str = z.split()
            try:
                addr = str[1]
                lbl = str[0]
            except:
                lbl = None
                pass
            if lbl == string:
                return addr
            hashValue = hashValue + 1 % prime
        return None

    def printer(self):
        for x in range(len(self.hashArray)):
            print self.hashArray[x]


# create SICOPS File

table = HashTable()
sicFile = open('SICOPS.txt')
r = sicFile.readline()


# GIVE EACH MNEMONIC A HASH VALUE
def findHashValue(mnem):
    global prime
    hashVal = 0
    for c in mnem:
        hashVal = (hashVal * 26 + ord(c)) % prime
    return hashVal


# STORE SICOPS.TXT IN A HASHTABLE (MENMONIC, OPCODE, BYTE SIZE)
while r:
    i = r.split()
    operate = Operations(i)
    try:
        hashValue = findHashValue(operate.mnem)
        string = operate.mnem + " " + operate.opcode + " " + operate.byteSize
        table.put(hashValue, string)
    except:
        print "something went wrong"
    r = sicFile.readline()
sicFile.close()

# Create Instructions -- Symbol Table -- Flags
SymTab = HashTable()
insList = []

f = open('file1.txt')
lines = f.readline()
# CREATE INSTRUCTIONS
while lines:
    i = lines.split()
    ins = Ins(i)
    hv = findHashValue(ins.opcode)
    byteSize = table.searchByteSize(hv, ins.opcode)
    opcode = table.searchNumOpcode(hv, ins.opcode)
    ins.set_hexOpcode(opcode)

    if byteSize is not None:
        ins.set_ByteSize(byteSize)

    # Create Symbol Table
    if ins.hasLabel:
        symHV = findHashValue(ins.label)
        lblAddress = ins.label + " " + str(ins.address)
        SymTab.put(symHV, lblAddress)

    i = lines.split()
    ins = Ins(i)
    hv = findHashValue(ins.opcode)
    # Get Byte Size
    byteSize = table.searchByteSize(hv, ins.opcode)
    # Get Hexadecimal Opcode
    opcode = table.searchNumOpcode(hv, ins.opcode)
    # Set Hexadecimal Opcode
    ins.set_hexOpcode(opcode)

    if byteSize is not None:
        ins.set_ByteSize(byteSize)

    # Calculate the Addresses
    ins.set_Address(lctr)
    # Set Byte Size
    if ins.byteSize == 0:
        if ins.opcode == "RESW" or ins.opcode == "RESB" or ins.opcode == "BYTE" or ins.opcode == "WORD":
            if ins.opcode == "WORD":
                ins.byteSize = 3
            if ins.opcode == "RESB":
                ins.byteSize = ins.operand
            if ins.opcode == "RESW":
                n = ins.operand
                ins.byteSize = int(n) * 3
            elif ins.opcode == "BYTE":
                if "C'" in ins.operand:
                    ss = ins.operand[1:]
                    size = len(ss) - 2
                    ins.byteSize = size
                elif "X" in ins.operand and "=" not in ins.operand:
                    ss = ins.operand[1:]
                    size = len(ss) - 2
                    if int(size) % 2 != 0:
                        print "Odd number of hex values"
                    size = int(size) / 2
                    ins.byteSize = size
                else:
                    print "NO QUOTES FOUND IN THE OPERAND FIELD AT ADDRESS "
        elif ins.opcode != "START" and ins.opcode != "BASE" and ins.opcode != "END":
            print "Not a valid mnemonic at address ", hex(ins.address)

    if ins.byteSize != "":
        lctr = lctr + int(ins.byteSize)

    # Create Symbol Table
    if ins.hasLabel:
        symHV = findHashValue(ins.label)
        lblAddress = ins.label + " " + str(ins.address)
        SymTab.put(symHV, lblAddress)
    insList.append(ins)
    lines = f.readline()

# table.printer()
# SymTab.printer()

# OBJECT CODE -- BASE ADDRESS -- FLAGS

for x, nextelem in zip(insList, insList[1:] + insList[:1]):
    one = ""
    two = ""
    three = ""
    # Create Flags
    if "+" in x.opcode:
        x.set_E(True)
    if x.operand.startswith("#"):
        x.set_I(True)
        if x.operand[1:].isdigit():
            x.set_P(False)
    if x.operand.startswith("@"):
        x.set_N(True)
    if ",X" in x.operand:
        x.set_X(True)
    if x.I is False and x.N is False:
        x.set_I(True)
        x.set_N(True)
    if x.operand is None:
        x.X = False
        x.B = False
        x.P = False
        x.E = False
    if x.opcode == "BASE":
        string = x.operand
        hashValue = findHashValue(string)
        baseAddress = SymTab.searchAddressofLbl(hashValue, string)
    # FIRST PART OF THE OBJECT CODE -- FIRST PART OF THE OBJECT CODE -- FIRST PART OF THE OBJECT CODE
    nixbpe = str(x.X) + "-" + str(x.B) + "-" + str(x.P) + "-" + str(x.E)
    # 3 and 4 byte instructions, Finding PC
    if x.opcode != "WORD" and x.opcode != "RESW" and x.opcode != "BYTE" and x.opcode != "RESB":
        if x.operand.startswith("#") or x.operand.startswith("@"):
            string = x.operand[1:]
            hashValue = findHashValue(string)
            var = SymTab.searchAddressofLbl(hashValue, string)
            x.PC = var
        elif ",X" in x.operand:
            strings = x.operand.split(",")
            string = strings[0]
            hashValue = findHashValue(string)
            var = SymTab.searchAddressofLbl(hashValue, string)
            x.PC = var
        else:
            string = x.operand
            hashValue = findHashValue(string)
            var = SymTab.searchAddressofLbl(hashValue, string)
            x.PC = var
        try:
            # First part of object Code
            if int(x.byteSize) == 3 or int(x.byteSize) == 4:
                op = int(x.hexOpcode, 16)
                if x.get_N() is True and x.get_I() is True:
                    one = op + 3
                elif x.N is True and x.I is False:
                    one = op + 2
                elif x.N is False and x.I is True:
                    one = op + 1
                elif x.N is False and x.I is False:
                    one = op
            # 2 byte instructions
            elif int(x.byteSize) == 2:
                op = int(x.hexOpcode, 16)
                one = op
            # For 3 and 4 Byte Instructions
            if nixbpe == "True-False-False-False":
                two = 8
            if nixbpe == "True-True-False-False":
                two = int("C", 16)
                three = int(x.PC) - int(baseAddress)
            if nixbpe == "True-False-True-False":
                two = int("A", 16)
                if x.operand[2:].isdigit():
                    three = x.operand
                else:
                    three = x.PC - nextelem.address
                    print three, "threeeeee"
                    # missing part
            if nixbpe == "True-False-False-True":
                two = 9
                three = x.PC
            if nixbpe == "False-True-False-False":
                two = 4
                three = x.PC - int(baseAddress)
            if nixbpe == "False-False-True-False":
                two = 2
                three = int(x.PC) - int(baseAddress)
            if nixbpe == "False-False-False-True":
                two = 1
            if nixbpe == "False-False-False-False":
                two = 0
            if one != "":
                # hexxx is part 1
                hexxx = int(one)
            else:
                hexxx = 0
            if two != "":
                # vv is part 2
                vv = int(two)
            else:
                vv = 0
            # Put all three parts together
            x.objectCode = hex(hexxx)[2:].zfill(2) + hex(vv)[2:]
        except:
            try:
                var = int(one)
                var2 = int(two)
                x.objectCode = hex(var)[2:].zfill(2) + hex(var2)[2:] + three
            except:
                pass
    if x.opcode == "RESW" or x.opcode == "BYTE" or x.opcode == "WORD" or x.opcode == "RESB":
        if x.opcode == "RESW":
            x.objectCode = "FFFFFF"
        elif x.opcode == "WORD":
            var = int(x.operand)
            x.objectCode = hex(var)[2:].zfill(6)
        elif x.opcode == "RESB":
            x.objectCode = "FFFFFF"
        elif x.opcode == "BYTE":
            pass

for x in insList:
    # x.PC needs not be an empty string and None so I can convert to int
    if x.PC is not None and x.PC != "":
        x.PC = int(x.PC)
    else:
        x.PC = ""
    try:
        print ("{:>10} {:>10} {:>10} {:>10} {:>10}".format(hex(x.address), x.label, x.opcode, x.operand, x.objectCode))
    except:
        print ("{:>10} {:>10} {:>10} {:>10} {:>10}".format(hex(x.address), x.label, x.opcode, x.operand, x.PC[2:]))
