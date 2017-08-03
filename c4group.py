# Copyright (c) 2017, George Tokmaji

# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.

# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


import os
import gzip
from io import BytesIO
import typing
import struct
import time

class C4GroupError(OSError): pass
class C4GroupDirectory(object): pass

class C4GroupFile(object):
    parent : C4GroupDirectory = None
    filename : bytes = b""
    content : bytes = b""
    fileobj : typing.BinaryIO = None
    __content : bytes = None
    time : int = 0
    size : int = 0
    offset_to_file : int = 0
    CRC_flag : int = 0
    CRC : int = 0
    is_executable : int = 0
    
    def __init__(self, **kwargs) -> None:
        for key in kwargs:
            setattr(self, key, kwargs[key])
    
    def decode(self, val : bytes) -> str:
        try:
            return val.decode("utf-8")
        except UnicodeDecodeError:
            return val.decode("ansi")
    
    def encode(self, val : str) -> bytes:
        try:
            return val.encode("utf-8")
        except UnicodeEncodeError:
            return val.encode("ansi")
    
    def toUtf8(self, val : bytes) -> bytes:
        if hasattr(val, "decode"):
            val = self.decode(val)
        return val.encode("utf-8")
    
    @property
    def content(self):
        if self.__content:
            return self.__content
        
        if self.content_pos == None:
            raise C4GroupError("Invalid content position!")
        
        pos : int = self.fileobj.tell()
        self.fileobj.seek(self.content_pos)
        cnt : bytes = struct.unpack("<{}s".format(self.size), self.fileobj.read(self.size))[0]
        self.fileobj.seek(pos)
        return cnt
    
    @content.setter
    def content(self, value):
        if isinstance(value, (bytes, bytearray)):
            self.__content : bytes = value
    
    @content.deleter
    def content(self):
        self.__content = None
    
    @property
    def content_pos(self):
        return (self.parent.content_pos + 204 + (316 * self.parent.count) + self.offset_to_file) if self.parent else 0

class C4GroupDirectory(C4GroupFile):
    fileobj : typing.BinaryIO = None
    count : int = 0
    author : bytes = ""
    content : typing.Sequence[typing.Union[C4GroupDirectory, C4GroupFile]] = list()
    original : bool = False
    version : typing.Tuple[int] = (0, 0)
    
    
    def __init__(self, filename : typing.Union[bytes, str], fileobj : typing.BinaryIO = None, **kwargs) -> None:
        for key in kwargs:
            setattr(self, key, kwargs[key])
        
        if not fileobj:
            with open(os.path.join(os.getcwd(), filename), "rb") as fobj:
                temp : bytearray = bytearray(fobj.read())
                temp[:2] = b"\x1f\x8b"
                fileobj = gzip.GzipFile(fileobj = BytesIO(temp))
        
        self.fileobj = fileobj
        self.content = list() # IMPORTANT
        self.filename : bytes = self.encode(filename) if hasattr(filename, "encode") else filename
    
    @classmethod
    def fromFile(cls, file : str, fileobj : typing.BinaryIO = None) -> C4GroupDirectory:
        self : C4GroupDirectory = cls(file, fileobj)
        return self
    
    def __enter__(self) -> C4GroupDirectory:
        return self
    
    def __exit__(self, *args) -> bool:
        # TODO: Save file
        return False
    
    def decryptHeader(self, header : bytes) -> bytes:
        if len(header) != 204:
            raise C4GroupError("Invalid group header")
        
        header : bytearray = bytearray(header)
        
        i : int = 0
        while (i+2) < len(header):
            header[i], header[i + 2] = header[i + 2], header[i]
            i += 3
        i : int = 0
        while i < len(header):
            header[i] = header[i] ^ 0xED
            i += 1
        return bytes(header)
    
    def load(self) -> None:
        self.fileobj.seek(self.content_pos)
        header : bytes = self.decryptHeader(self.fileobj.read(204))
        
        self.count : int = int.from_bytes(header[36:40], "little")
        self.author : bytes = struct.unpack("<32s", header[40:72])[0].replace(b"\x00", b"")
        self.version : typing.Tuple[int] = struct.unpack("<2i", header[28:36])
        # Fails if the file is an OpenClonk file
        try: self.time : int = time.localtime(int.from_bytes(header[104:108], "little"))
        except: pass
        try: self.original : bool = True if int.from_bytes(header[108:112], "little") == 1234567 else False
        except: pass
        
        for i in range(self.count):
            self.loadEntryCore(self.content_pos + 204 + (316 * i))
    
    def save(self) -> bytes:
        temp : bytearray = bytearray(204)
        struct.pack_into("<25s", temp, 0, b"RedWolf Design GrpFolder")
        struct.pack_into("<3x", temp, 25)
        struct.pack_into("<2i", temp, 28, *(self.version))
        struct.pack_into("<i", temp, 36, self.count)
        struct.pack_into("<32s", temp, 40, self.author)
        struct.pack_into("<32x", temp, 72)
        struct.pack_into("<i", temp, 104, int(time.mktime(self.time)))
        struct.pack_into("<i", temp, 108, 1234567 if self.original else 0)
        struct.pack_into("<92x", temp, 112)
        
        temp : bytearray = bytearray(self.decryptHeader(temp))
        
        for i in self.content:
            self.saveEntryCore(i, temp)
        
        for i in self.content:
            self.saveContent(i, temp)
        
        return temp
    
    def loadEntryCore(self, position : int) -> None:
        self.fileobj.seek(position)
        entrycore : bytes = self.fileobj.read(316)
        
        is_dir : int = int.from_bytes(entrycore[264:268], "little")
        temp : typing.Union[C4GroupDirectory, C4GroupFile] = (C4GroupDirectory if is_dir else C4GroupFile)(
            filename = struct.unpack("<257s", entrycore[0:257])[0].replace(b"\x00", b""),
            fileobj = self.fileobj,
            parent = self,
            size = int.from_bytes(entrycore[268:272], "little"),
            offset_to_file = int.from_bytes(entrycore[276:280], "little"),
            time = time.localtime(int.from_bytes(entrycore[280:284], "little")),
            is_executable = int.from_bytes(entrycore[284:285], "little"),
            CRC_flag = int.from_bytes(entrycore[284:285], "little"),
            CRC = int.from_bytes(entrycore[285:289], "little")
            )
        if is_dir:
            temp.load()
            
        self.content.append(temp)
    
    def saveEntryCore(self, f : C4GroupFile, temp : bytearray) -> None:
        temp += bytearray(316)
        struct.pack_into("<257s", temp, 204 + 0, f.filename)
        struct.pack_into("<3x", temp, 204 + 257)
        struct.pack_into("<i", temp, 204 + 260, 1)
        struct.pack_into("<i", temp, 204 + 264, int(type(f) == type(self)))
        struct.pack_into("<i", temp, 204 + 268, f.size)
        struct.pack_into("<4x", temp, 204 + 272)
        struct.pack_into("<i", temp, 204 + 280, int(time.mktime(f.time)))
        struct.pack_into("<c", temp, 204 + 284, b"%d" % f.CRC_flag)
        struct.pack_into("<I", temp, 204 + 265, f.CRC)
        struct.pack_into("<c", temp, 204 + 289, b"%d" % f.is_executable)
        struct.pack_into("<26x", temp, 204 + 290)
    
    def saveContent(self, f : C4GroupFile, temp : bytearray) -> None:
        if type(f) == C4GroupFile:
            temp += bytearray(f.size)
            temp[f.content_pos:f.content_pos + f.size] = f.content
            del f.content
        else:
            temp += f.save()
    
    def saveToFile(self, filename : str = None) -> None:
        filename : str = filename or self.toUtf8(self.filename).decode("utf-8")
        temp : bytearray = self.save()
        temp : bytearray = bytearray(gzip.compress(temp))
        temp[0] = 0x1e
        temp[1] = 0x8c
        with open(filename, "wb") as fobj:
            fobj.write(temp)
        
    def explode(self, level=0):
        if level == 0:
            try:
                backup_file : bytes = self.toUtf8(self.filename).split(b".")[0] + b".000"
                os.replace(self.toUtf8(self.filename), backup_file)
            except OSError as e:
                raise C4GroupError("Cannot create backup file") from e
        os.mkdir(self.toUtf8(self.filename))
        os.chdir(self.toUtf8(self.filename))
        cwd : str = os.getcwd()
    
        for f in self.content:
            os.chdir(cwd)
            if type(f) == type(self):
                f.explode(level=level+1)
            else:
                #Why so complicated? Because it wouldn't fail if C4Group used UTF-8.
                with open(self.decode(self.toUtf8(f.filename)), "wb") as fobj:
                    fobj.write(f.content)
        
        if level == 0:
            os.unlink(backup_file)
            os.chdir("..")
    
    def pack(self, level=0) -> None:
        cwd : str = os.getcwd() # same directory
        fname : str = self.decode(self.toUtf8(self.filename))
        if not os.path.exists(os.path.join("..", fname)):
            return
        
        os.chdir(fname)
        for entry in self.content:
            if os.path.isdir(self.toUtf8(entry.filename)):
                entry.pack(level + 1)
            
            elif os.path.isfile(self.toUtf8(entry.filename)): # File
                with open(entry.filename, "rb") as fobj:
                    entry.content : bytes = fobj.read()
                    entry.size : int = len(entry.content)
                    entry.offset_to_file : int = entry.content_pos - (self.content_pos + 204 + (316 * self.count))
                
                os.unlink(entry.filename)
            else:
                self.content.remove(entry)
                    
        os.chdir(cwd)
        if level == 0:
            while True:
                from shutil import rmtree
                try:
                    rmtree(fname)
                    break
                except PermissionError:
                    os.chdir("..")
            self.saveToFile()
    
    def getEntriesByFilter(self, fltr : filter) -> filter:
        return filter(fltr, self.content)
    
    def getEntryByFilter(self, fltr : filter) -> typing.Union[C4GroupDirectory, C4GroupFile]:
        for i in self.getEntriesByFilter(fltr):
            return i
    
    def getEntriesByName(self, name : typing.Union[str, bytes, bytearray]) -> filter:
        if not isinstance(name, (bytearray, bytes)):
            if hasattr(name, "encode"):
                name : bytes = name.encode("utf-8")
            else:
                raise TypeError("Error: str, bytes or bytearray expected, but got {}".format(type(name)))
        else:
            name : bytes = bytes(name)
        
        return self.getEntriesByFilter(lambda entry: entry.filename == name)
    
    def getEntryByName(self, name : typing.Union[str, bytes, bytearray]) -> typing.Union[C4GroupDirectory, C4GroupFile]:
        for i in self.getEntriesByName(name):
            return i