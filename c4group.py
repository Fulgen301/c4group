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
import struct
import time

class C4Group(gzip.GzipFile):
	def __init__(self, filename, mode=None, compresslevel=9, fileobj=None, mtime=None, encoding="ansi"):
		filename = os.path.join(os.getcwd(), filename)
		if not fileobj:
			with open(filename, "rb") as fobj:
				temp = bytearray(fobj.read())
				temp[0] = 0x1f
				temp[1] = 0x8b
			fileobj = BytesIO(temp)
		
		self.encoding = encoding
		super(C4Group, self).__init__(filename, mode, compresslevel, fileobj, mtime)

class C4GroupError(OSError): pass

class C4GroupFile(object):
	parent = None
	filename = b""
	content = b""
	fileobj = None
	content_pos = None
	time = 0
	size = 0
	offset_to_file = 0
	CRC_flag = 0
	CRC = 0
	is_executable = 0
	
	def __init__(self, fileobj):
		self.fileobj = fileobj
	
	def decode(self, val):
		try:
			return val.decode("utf-8")
		except UnicodeDecodeError:
			return val.decode("ansi")
	
	def encode(self, val):
		try:
			return val.encode("utf-8")
		except UnicodeEncodeError:
			return val.encode("ansi")
	
	def toUtf8(self, val):
		if hasattr(val, "decode"):
			val = self.decode(val)
		return val.encode("utf-8")
	
	@property
	def content(self):
		if self.content_pos == None:
			raise C4GroupError("Invalid content position!")
		
		pos = self.fileobj.tell();
		self.fileobj.seek(self.content_pos)
		cnt = struct.unpack("<{}s".format(self.size), self.fileobj.read(self.size))[0]
		self.fileobj.seek(pos)
		return cnt
		

class C4GroupDirectory(C4GroupFile):
	fileobj = None
	count = 0
	author = ""
	content = list()
	original = 1234567
	version = (0, 0)
	header_offset = 0
	
	
	def __init__(self, fileobj : C4Group, offset : int = 0) -> None:
		self.content = list()
		self.fileobj = fileobj
		self.header_offset = offset
		self.filename = self.encode(fileobj.filename) if hasattr(fileobj.filename, "encode") else fileobj.filename
	
	def setOffset(self, offset : int) -> None:
		self.header_offset = offset
	
	def decryptHeader(self, header : bytes) -> bytes:
		if len(header) != 204:
			raise C4GroupError("Invalid group header")
		
		header = bytearray(header)
		
		i = 0
		while (i+2) < len(header):
			header[i], header[i + 2] = header[i + 2], header[i]
			i += 3
		i = 0
		while i < len(header):
			header[i] = header[i] ^ 0xED
			i += 1
		return bytes(header)
	
	def load(self) -> None:
		self.fileobj.seek(self.header_offset)
		header = self.decryptHeader(self.fileobj.read(204))
		
		self.count = int.from_bytes(header[36:40], "little")
		self.author = struct.unpack("<32s", header[40:72])[0].replace(b"\x00", b"")
		self.version = struct.unpack("<2i", header[28:36])
		# Fails if the file is an OpenClonk file
		try: self.time = time.localtime(int.from_bytes(header[104:108], "little"))
		except: pass
		try: self.original = True if int.from_bytes(header[108:112], "little") == 1234567 else False
		except: pass
		
		for i in range(self.count):
			self.loadEntryCore(self.header_offset + 204 + (316 * i))
	
	def save(self) -> bytes:
		temp = bytearray(204)
		struct.pack_into("<25s", temp, 0, b"RedWolf Design GrpFolder")
		struct.pack_into("<3x", temp, 25)
		struct.pack_into("<2i", temp, 28, *(self.version))
		struct.pack_into("<i", temp, 36, self.count)
		struct.pack_into("<32s", temp, 40, self.author)
		struct.pack_into("<32x", temp, 72)
		struct.pack_into("<i", temp, 104, time.mktime(self.time))
		struct.pack_into("<i", temp, 108, 1234567 if self.original else 0)
		struct.pack_into("<92x", temp, 112)
		
		for i in self.content:
			self.saveEntryCore(i, temp)
		
		for i in self.content:
			self.saveContent(i, temp)
	
	def loadEntryCore(self, position : int) -> None:
		self.fileobj.seek(position)
		entrycore = self.fileobj.read(316)
		
		is_dir = int.from_bytes(entrycore[264:268], "little")
		if is_dir:
			temp = C4GroupDirectory(self.fileobj)
		else:
			temp = C4GroupFile(self.fileobj)
		
		temp.parent = self
		temp.filename = struct.unpack("<257s", entrycore[0:257])[0].replace(b"\x00", b"")
		temp.size = int.from_bytes(entrycore[268:272], "little")
		temp.offset_to_file = int.from_bytes(entrycore[276:280], "little")
		try: temp.time = time.localtime(int.from_bytes(entrycore[280:284], "little"))
		except: pass
		temp.is_executable = int.from_bytes(entrycore[289:290], "little")
		temp.CRC_flag = int.from_bytes(entrycore[284:285], "little")
		if temp.CRC_flag:
			temp.CRC = int.from_bytes(entrycore[285:289], "little")
		
		temp.content_pos = self.header_offset + 204 + (316 * self.count) + temp.offset_to_file
		if is_dir:
			temp.setOffset(temp.content_pos)
			temp.load()
			
		self.content.append(temp)
	
	def saveEntryCore(self, f : C4GroupFile, temp : bytearray) -> None:
		temp += bytearray(316)
		struct.pack_into("<257s", temp, 0, f.filename)
		struct.pack_into("<3x", temp, 257)
		struct.pack_into("<i", temp, 260, 1)
		struct.pack_into("<i", temp, 264, int(type(f) == type(self)))
		struct.pack_into("<i", temp, 268, f.size)
		struct.pack_into("<4x", temp, 272)
		struct.pack_into("<i", temp, 280, time.mktime(f.time))
		struct.pack_into("<c", temp, 284, f.CRC_flag)
		struct.pack_into("<I", temp, 265, f.CRC)
		struct.pack_into("<c", temp, 289, f.is_executable)
		struct.pack_into("<26x", temp, 290)
	
	def saveContent(self, f : C4GroupFile, temp : bytearray) -> None:
		pass
	
	def explode(self, level=0):
		if level == 0:
			try:
				backup_file = self.toUtf8(self.filename).split(b".")[0] + b".000"
				os.replace(self.toUtf8(self.filename), backup_file)
			except OSError as e:
				raise C4GroupError("Cannot create backup file") from e
		os.mkdir(self.toUtf8(self.filename))
		os.chdir(self.toUtf8(self.filename))
		cwd = os.getcwd()
	
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
		
	
if __name__ == "__main__":
	while True:
		f = input("Enter the path of the file:\n> ")
		if not os.path.isfile(f):
			print("Invalid path!")
		break
	
	file = C4GroupDirectory(C4Group(f), 0)