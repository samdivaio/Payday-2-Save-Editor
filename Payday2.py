# coding=utf-8

import hashlib
import sys
import shutil
import os
import os.path
from binascii import b2a_hex
from collections import OrderedDict, namedtuple
from struct import pack, unpack_from

SizedInt = namedtuple('SizedInt', ['size', 'value'])
size_to_c_name = {1: 'byte', 2: 'short', 4: 'int'}
SizedInt.__str__ = lambda self: "%s(%s)" % (size_to_c_name[self.size], self.value)


class ParseException(Exception):
    pass


class SerializeException(Exception):
    pass


class PaydaySave(OrderedDict):
    magic = '\x0A\x00\x00\x00'

    def __init__(self, filename="save098.sav", *args, **kwargs):
        super(PaydaySave, self).__init__(*args, **kwargs)

        self.prologue = None
        self.epilogue = None

        self.payload = None

        self.treehash = None
        self.filehash = None

        self.filename = filename
        with open(filename, "rb") as from_file:
            self.__from_file(from_file.read())

    def regen_payload(self):
        self.payload = PaydaySave.__gen_tree(self)
        self.__verify_and_update_hashes()

    def save(self, filename=None, do=True):
        if filename is None:
            filename = self.filename

        if do:
            self.regen_payload()
        bytes_total = self.__bytes() + self.filehash
        bytes_total = PaydaySave.__xor_stream(bytes_total)

        with open(filename, "wb") as file_save:
            file_save.write(bytes_total)

    def change_user_id(self, new_user_id):
        with open(self.filename, "rb") as file_dec:
            file_xor = PaydaySave.__xor_stream(file_dec.read())
            file_xor = file_xor.replace(self.userID, new_user_id)
            self.payload = file_xor
            self.__verify_and_update_hashes()

            f = open("newsave098.sav", "wb")
            f.write(PaydaySave.__xor_stream(file_xor + self.filehash))
            f.close()

    def __from_file(self, file_dec):
        file_xor = PaydaySave.__xor_stream(file_dec)
        if file_xor[0:4] != PaydaySave.magic:
            raise ParseException("unsupported format (0x%08x) or decode error!" % b2a_hex(file_xor[0:4]))

        prologue_length = unpack_from("<I", file_xor, 4)[0]
        prologue_end = 8 + prologue_length
        self.prologue = file_xor[8:prologue_end]

        tree_length_from_file = unpack_from("<I", file_xor, prologue_end)[0]
        if file_xor[prologue_end+4:prologue_end+8] != PaydaySave.magic:
            raise ParseException("unsupported format (0x%08x) or decode error!" %
                                 b2a_hex(file_xor[prologue_end+4:prologue_end+8]))

        """print "TreeStruct begin offset: 0x%04x" % (prologue_end + 8)
        print "TreeStruct length: 0x%04x" % tree_length_from_file
        print """""

        tree_length, root = self.__parse_tree(file_xor, prologue_end + 9)
        if tree_length + 0x15 != tree_length_from_file:
            raise ParseException("Expecting X bytes of TreeStruct data but got X!")

        tree_end = prologue_end + 8 + tree_length + 1
        super(PaydaySave, self).update(root)

        """print ""
        print "TreeStruct end offset: 0x%04x" % tree_end"""

        self.payload = file_xor[prologue_end+8:tree_end]
        self.treehash = file_xor[tree_end:tree_end+0x10]
        self.epilogue = file_xor[tree_end+0x10:-0x10]
        self.filehash = file_xor[-0x10:]

        self.__verify_and_update_hashes()

    def __verify_and_update_hashes(self):
        calc_treehash = PaydaySave.__hash_main(self.payload)
        if self.treehash != calc_treehash:
            """if not silent:
                print "WARNING: TreeStruct hash was invalid! Will fix on save."
                print "WARNING: from file: %s" % b2a_hex(self.treehash)
                print "WARNING: was: %s" % b2a_hex(calc_treehash)"""
            self.treehash = calc_treehash
        """elif not silent:
            print "TreeStruct hash: %s (valid)" % b2a_hex(self.treehash)"""

        calc_filehash = PaydaySave.__hash_final(self.__bytes())
        if self.filehash != calc_filehash:
            """if not silent:
                print "WARNING: File hash was invalid! Will fix on save."
                print "WARNING: from file: %s" % b2a_hex(self.filehash)
                print "WARNING: was: %s" % b2a_hex(calc_filehash)"""
            self.filehash = calc_filehash
        """elif not silent:
            print "File hash: %s (valid)" % b2a_hex(self.filehash)"""

    def __bytes(self):
        return PaydaySave.magic + pack("<I", len(self.prologue)) + self.prologue \
               + pack("<I", len(self.payload) + 0x14) + PaydaySave.magic + self.payload + self.treehash + self.epilogue

    def __parse_tree(self, data, at=0, level=0):
        def parse_string(pos):
            end = pos
            while data[end] != '\x00':
                end += 1
            return end - pos + 1, data[pos:end]

        type_parsers = {
            '\x01': parse_string,
            '\x02': lambda pos: (4, unpack_from("<f", data, pos)[0]),
            '\x03': lambda pos: (0, None),
            '\x04': lambda pos: (1, SizedInt(1, ord(data[pos]))),
            '\x05': lambda pos: (2, SizedInt(2, unpack_from("<H", data, pos)[0])),
            '\x06': lambda pos: (1, data[pos] == '\x01'),
            '\x07': lambda pos: self.__parse_tree(data, pos, level + 1)
        }

        def try_get_parser(offset):
            if not data[offset] in type_parsers:
                raise ParseException("unknown data type (0x%02x) @ 0x%04x! next 4 bytes: %s" % (ord(data[offset]),
                    offset, b2a_hex(data[offset + 1:offset + 5])))
            return type_parsers[data[offset]]

        count = unpack_from("<I", data, at)[0]
        root = OrderedDict()
        offset = 4

        for x in xrange(count):
            data_len, key = try_get_parser(at + offset)(at + offset + 1)
            offset += data_len + 1

            data_len, value = try_get_parser(at + offset)(at + offset + 1)
            offset += data_len + 1
            if not isinstance(value, OrderedDict):
                if key == "user_id":
                    self.userID = str(value)

            root[key] = value

        return offset, root

    @staticmethod
    def __gen_tree(tree):
        import types
        serializers = {
            str: lambda data: "\x01" + data + "\x00",
            float: lambda data: "\x02" + pack("<f", data),
            types.NoneType: lambda data: "\x03",
            SizedInt: lambda data: {
                1: lambda x: "\x04" + chr(x),
                2: lambda x: "\x05" + pack("<H", x),
            }[data.size](data.value),
            bool: lambda data: "\x06\x01" if data else "\x06\x00",
            OrderedDict: PaydaySave.__gen_tree
        }

        def try_get_serializer(data):
            if not type(data) in serializers:
                raise SerializeException("unserializable type '%s'!" % type(data))
            return serializers[type(data)]

        payload = "\x07" + pack("<I", len(tree))
        for key, value in tree.items():
            payload += try_get_serializer(key)(key)
            payload += try_get_serializer(value)(value)

        return payload

    @staticmethod
    def __xor_stream(data):
        xor_key = [ord(x) for x in "t>?\xA42C&.#67jm:HG=S-cAk)8jh_MJh<nf\xF6"]
        xor_key_len = len(xor_key)

        data_len = len(data)
        data = (ord(x) for x in data)

        def key_idx(i):
            return ((data_len + i) * 7) % xor_key_len

        data = ((byte ^ (xor_key[key_idx(i)] * (data_len - i))) % 256 for i, byte in enumerate(data))

        return "".join((chr(x) for x in data))

    @staticmethod
    def __hash_main(data):
        return hashlib.md5(data).digest()

    @staticmethod
    def __hash_final(data):
        key = [ord(x) for x in "\x1A\x1F2,"]
        data = (ord(x) for x in data)
        data = (i % 7 if ((x + key[i % 4]) % 2) else x for i, x in enumerate(data))
        data = "".join((chr(x) for x in data))

        return hashlib.md5(data).digest()

    def get_id(self):
        return self.userID

    @staticmethod
    def get_folder():
        batch = open("location.bat", "w+")
        batch.write("@echo off\n")
        batch.write("setlocal\n")
        batch.write("set \"psCommand=\"(new-object -COM 'Shell.Application')^\n")
        batch.write(".BrowseForFolder(0,'Please select Payday 2 save folder.',0,0).self.path\"\"\n")
        batch.write("for /f \"usebackq delims=\" %%I in (`powershell %psCommand%`) do set \"folder=%%I\"\n")
        batch.write("setlocal enabledelayedexpansion\n")
        batch.write("echo !folder!\n")
        batch.write("endlocal\n")
        batch.close()

        fh = os.popen("location.bat")
        output = fh.read()
        os.remove("location.bat")
        return output.replace("\n", "").replace("\r", "") + "\\"


def main():
    location = PaydaySave.get_folder()
    if not os.path.isfile(location + "save098.sav"):
        print "ERROR: \"" + location + "save098.sav\" does not exist."
        sys.exit(0)
    option = "0"
    while option != "6":
        print "Enter 1 to change steam user ID of saving"
        print "Enter 2 to backup the old save"
        print "Enter 3 to active the new save"
        print "Enter 4 to load backup"
        print "Enter 5 to get the Steam64ID in the save098.sav file"
        print "Enter 6 to exit"
        option = raw_input(">>> ")
        if option == "1":  # Change ID
            try:
                save = PaydaySave(location + "save098.sav")
            except:
                print "*** ERROR: Save file is corrupted"
                continue

            print "Check https://steamid.io/ for Steam64ID"
            new_id = raw_input("New user ID (Steam64ID): ")
            save.change_user_id(new_id)
            save2 = PaydaySave(location + "newsave098.sav")
            print "Old steam ID: " + save.get_id()
            print "New steam ID: " + save2.get_id()
            print "Done successfully."
        elif option == "2":  # Backup
            if not os.path.isfile(location + "save098.sav.backup"):
                shutil.copy2(location + "save098.sav", location + "save098.sav.backup")
            else:
                override = raw_input("WARNING: Backup is already exist, override? (y/n) ")
                override = override.lower()
                if override == "y":
                    shutil.copy2(location + "save098.sav", location + "save098.sav.backup")
            print "Done successfully."
        elif option == "3":  # Put new save
            is_backup = raw_input("WARNING! Do you have a backup? (y/n) ")
            is_backup = is_backup.lower()
            if is_backup == 'y':
                if os.path.isfile(location + "newsave098.sav"):
                    if os.path.isfile(location + "save098.sav"):
                        os.remove(location + "save098.sav")
                    os.rename(location + "newsave098.sav", location + "save098.sav")
                else:
                    print "WARNING: New save file is not exist."
                    continue
                print "Done successfully."
            else:
                print "ERROR: Backup does not exist."
        elif option == "4":  # load backup
            confirm = raw_input("WARNING! Load old backup? (y/n) ")
            confirm = confirm.lower()
            if confirm == 'y':
                if os.path.isfile(location + "save098.sav.backup"):
                    os.remove(location + "save098.sav")
                    os.rename(location + "save098.sav.backup", location + "save098.sav")
                    print "Done successfully."
                else:
                    print "ERROR: Backup does not exist."
        elif option == "5":  # get Steam64ID
            try:
                save = PaydaySave(location + "save098.sav")
            except:
                print "*** ERROR: Save file is corrupted"
                continue
            print "Steam64ID inside save098.sav is: " + save.get_id()
        elif option != "6":
            print "Unknown option."

if __name__ == '__main__':
    main()
