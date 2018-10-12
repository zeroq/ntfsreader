#!/opt/local/bin/python2.7
# coding: utf-8

"""
ntfsReader.py - v0.3 - 2018.10.12

Author : Jan Goebel - goebel@pi-one.net
Licence : GPL v2

Example Usage:
	# To display the partitions on a device
	python ntfsReader.py /dev/sda --part

	# To display all MFT entries of all NTFS partitions on a device
	python ntfsReader.py /dev/sda --mft

        # To display all MFT entries of a VMDK file
        python ntfsReader.py <path_to_vmdk> --vmdk --mft
"""

############################################################################
# General Information
############################################################################

__author__ = "jan goebel (goebel@pi-one.net)"
__version__ = "0.3"

############################################################################
# Imports
############################################################################

import sys
import struct
import time
import argparse
import os

############################################################################

def readAttribute(entry, offset, numA):
	"""
	read MFT attributes
	"""
	#for num in range(0,numA+1):
        num = 0
        while offset < 1024:
                print offset
		### gather values
		try:
			type_ = struct.unpack('I',entry[offset:offset+4])[0] # Attribute Type Code
			asize = struct.unpack('I',entry[offset+4:offset+8])[0]
			nonresidentflag = hex(struct.unpack('B',entry[offset+8])[0])
			lenname = entry[offset+9]
			offsetname = entry[offset+10:offset+12]
			aflags = entry[offset+12:offset+14]
			aid = entry[offset+14:offset+16]
		except:
			break
		### output values
		print "Count: %s" % (num)
                atypes = {16: '$STANDARD_INFORMATION (16)', 48: '$FILE_NAME (48)', 64: '$OBJECT_ID (64)', 128: '$DATA (128)', 144: '$INDEX_ROOT (144)'}
                try:
                        if type_ < 193:
		                print "Attribute Type: %s" % (atypes[type_])
                        else:
                                print "Attribute Type: %s (Probably Slack)" % type_
                except KeyError:
		        print "Attribute Type: %s" % (type_)
		print "Attribute Size: %s" % (asize)
		print "Non-Resident Flag: %s" % (nonresidentflag)
		if nonresidentflag == '0x0':
			try:
				contentsize = struct.unpack('I',entry[offset+16:offset+20])[0]
				coff = struct.unpack('H',entry[offset+20:offset+22])[0]
			except:
				#print [entry]
				#sys.exit(255)
				break
			print "Content Size: %s" % (contentsize)
			print "Content Offset: %s" % (coff)
			coff = offset + coff
                        #print [entry[coff:coff+10]]
		else:
			### FIXME: handle non-resident mft entries
			type_ = 128
                        print "Non-resident MFT Entry"
                        coff = offset
                        contentsize = None
		if type_==16: # STANDARD_INFORMATION
			### gather values
			create = int(struct.unpack('Q',entry[coff:coff+8])[0])
			modify = int(struct.unpack('Q',entry[coff+8:coff+16])[0])
			change = int(struct.unpack('Q',entry[coff+16:coff+24])[0])
			access = int(struct.unpack('Q',entry[coff+24:coff+32])[0])
			perms = hex(struct.unpack('I',entry[coff+32:coff+36])[0])
			### output values
			print "$Standard_Info Entry"
			try:
				print "File Creation Time: %s" % (time.ctime((create-116444736000000000)/10000000))
			except:
				print "File Creation Time: %s" % ([create])
			try:
				print "File Last Modification Time: %s" % (time.ctime((modify-116444736000000000)/10000000))
			except:
				print "File Last Modification Time: %s" % ([modify])
			try:
				print "File Last MFT Change Time: %s" % (time.ctime((change-116444736000000000)/10000000))
			except:
				print "File Last MFT Change Time: %s" % ([change])
			try:
				print "File Last Access Time: %s" % (time.ctime((access-116444736000000000)/10000000))
			except:
				print "File Last Access Time: %s" % ([access])
			print "DOS File Permissions: %s" % (perms)
		elif type_==48: # FILE_NAME
			### gather values
			seqnum = int(struct.unpack('I',entry[coff:coff+4])[0])
			parentref = int(struct.unpack('>I',entry[coff+4:coff+8])[0])
			create = int(struct.unpack('Q',entry[coff+8:coff+16])[0])
			modify = int(struct.unpack('Q',entry[coff+16:coff+24])[0])
			change = int(struct.unpack('Q',entry[coff+24:coff+32])[0])
			access = int(struct.unpack('Q',entry[coff+32:coff+40])[0])
			fsize = int(struct.unpack('Q',entry[coff+40:coff+48])[0])
			realsize = int(struct.unpack('Q',entry[coff+48:coff+56])[0])
			flags = hex(struct.unpack('I',entry[coff+56:coff+60])[0])
			reparseval = struct.unpack('I',entry[coff+60:coff+64])[0]
			fnlen = int(struct.unpack('B',entry[coff+64])[0])
			nspace = int(struct.unpack('B',entry[coff+65])[0])
			namespace = {}
			namespace[0] = "POSIX"
			namespace[1] = "Win32"
			namespace[2] = "DOS"
			namespace[3] = "Win32 & DOS"
			fname = entry[coff+66:coff+66+fnlen+fnlen]
			### output values
			print "$File_Name Entry"
			print "Sequence Number: %s (%s)" % (seqnum, [entry[offset+8:offset+12]])
			print "Parent Reference: %s (%s)" % (parentref, [entry[offset+12:offset+16]])
			try:
				print "File Creation Time: %s" % (time.ctime((create-116444736000000000)/10000000))
			except:
				print "File Creation Time: %s" % ([create])
			try:
				print "File Last Modification Time: %s" % (time.ctime((modify-116444736000000000)/10000000))
			except:
				print "File Last Modification Time: %s" % ([modify])
			try:
				print "File Last MFT Change Time: %s" % (time.ctime((change-116444736000000000)/10000000))
			except:
				print "File Last MFT Change Time: %s" % ([change])
			try:
				print "File Last Access Time: %s" % (time.ctime((access-116444736000000000)/10000000))
			except:
				print "File Last Access Time: %s" % ([access])
			print "Allocated File Size: %s" % (fsize)
			print "Real Size: %s" % (realsize)
			print "Flags: %s (%s)" % (flags, [entry[offset+64:offset+68]])
			print "Reparse Value: %s" % (reparseval)
			print "Filename Length: %s" % (fnlen)
			try:
				print "Namespace: %s (%s)" % (nspace, namespace[nspace])
			except KeyError:
				print "Namespace: %s (UNKNOWN)" % (nspace)
                        try:
                                print "Filename: %s" % (fname.decode('utf-16').encode('utf-8'))
                        except:
                                print "Filename: %s" % ([fname])
		elif type_==128: # DATA
			print "$Data Entry"
                        if contentsize:
                                print [entry[coff:coff+contentsize]]
                        else:
                                print [entry[coff:]]

		### move
                if asize > 0:
                        offset = offset+asize
                        num += 1
                        print
                else:
                        break

############################################################################

def bruteMFT(pStuff, fp):
    """do not follow sectorsize to gather MFT records
    """

    print
    print "=== Brute MFT Entries ==="
    cnt = -1
    fp.seek(0,0)
    bytesRead = 0

    while True:
        entry = fp.read(4)
        bytesRead += 4
	if bytesRead > pStuff['psize']:
            print "reached end of partition"
            break
        signature = entry[0:4]
	if signature!="FILE" and signature!="BAAD":
            continue
        #entry = entry+fp.read(1024-4)
        entry = entry+fp.read(pStuff['sectorsize']*2-4)
	fixupSize = struct.unpack('H',entry[6:8])[0]
        flags = int(struct.unpack('H',entry[22:24])[0])
        if flags not in [0, 1, 2, 3, 5, 9, 13]:
            continue
	attribOff = struct.unpack('H',entry[20:22])[0]
	readAttribute(entry, attribOff, fixupSize)
        #bytesRead += 512
        cnt += 1
    return fp

############################################################################

def examineMFT(args, pStuff, fp):
	"""
	examine a MFT entry
	"""
	print pStuff
	print "=== MFT Entries ==="
	cnt = -1
	fp.seek(pStuff['mft']-512, 1)

	bytesRead = 0

	while True:
		entry = fp.read(pStuff['sectorsize']*2)
		bytesRead += pStuff['sectorsize']*2
		if bytesRead > pStuff['psize']:
			print "reached end of partition"
			break
		### gather values
		signature = entry[0:4]
		#if signature!="FILE" and signature!="BAAD" and signature!='\x00\x00\x00\x00':
		if signature!="FILE" and signature!="BAAD":
			#print "Invalid Signature found: %s" % ([signature])
			continue
			#break
		cnt += 1
		fixupOff = struct.unpack('H',entry[4:6])[0]
		fixupSize = struct.unpack('H',entry[6:8])[0]
		lsn = entry[8:16]
		seqval = struct.unpack('H',entry[16:18])[0]
		linkcount = struct.unpack('H',entry[18:20])[0]
		attribOff = struct.unpack('H',entry[20:22])[0]
		flags = struct.unpack('H',entry[22:24])[0]
		fl = {}
		fl[0] = "file unallocated"
		fl[1] = "file allocated"
		fl[2] = "folder unallocation"
		fl[3] = "folder allocation"
		fl[5] = "unknown"
		fl[9] = "unknown"
		fl[13] = "unknown"
		sizeMFTentry = struct.unpack('I',entry[24:28])[0]
		allocsizeMFTentry = entry[28:32]
		fpbaseRef = struct.unpack('Q',entry[32:40])[0]
		nextattribid = struct.unpack('H',entry[40:42])[0]
		rest = entry[42:]
		### output values
		print "=== MFT Entry: %s ===" % (cnt)
		print "Signature: %s" % (signature)
		print "MFT Entry Size: %s" % (sizeMFTentry)
		print "Relative Offset to Fixup Array: %s" % (fixupOff)
		print "Number of entries in Fixup Array: %s" % (fixupSize)
		print "Sequence Value: %s" % (seqval-1)
		print "Link Count: %s" % (linkcount)
		print "Relative Offset to first Attribute: %s" % (attribOff)
		try:
			print "Flags: %s (%s)" % (flags, fl[flags])
		except KeyError:
			print "Flags: %s (%s)" % (flags, 'unknown')
		print "Parent MFT: %s" % (fpbaseRef)
		print "Next Attribute ID: %s" % (nextattribid)

		print "=== Attributes ==="
		readAttribute(entry, attribOff, fixupSize)
	return fp

############################################################################

def examineNTFS(args, p, fp):
	"""
	examine NTF boot sector
	"""
	fpos = p['lbafirstsector']*512
	fp.seek(fpos, 0)
	bootSector = fp.read(512)
	jmp = bootSector[0:3]
	oem = bootSector[3:11]
	bytesPerSector = bootSector[11:13]
	secsCluster = bootSector[13]
	clusterSize = struct.unpack('H', bytesPerSector)[0]*struct.unpack('B', secsCluster)[0]
	mediaDescr = bootSector[21]
	totalSectors = bootSector[40:48]
	lcnmft = bootSector[48:56]
	lcnmftMirr = bootSector[56:64]
	sectorSize = int(struct.unpack('H', bytesPerSector)[0])
	if not args.sectorsize:
		args.sectorsize = sectorSize
	if args.boot:
		print "=== Boot Sector ==="
		print "Jump Instruction: %s" % (jmp.encode('hex'))
		print "OEM ID: %s" % (oem)
		if args.sectorsize == sectorSize:
			print "Bytes per Sector: %s" % (sectorSize)
		else:
			print "Bytes per Sector: %s (User set: %s)" % (sectorSize, args.sectorsize)
		print "Sectors per Cluster: %s" % (struct.unpack('B', secsCluster))
		print "Cluster Size: %s" % (clusterSize)
		print "Media Descriptor: %s" % ([mediaDescr])
		print "Total Sectors: %s" % (struct.unpack('Q', totalSectors))
		print "Logical Cluster Number MFT: %s" % (struct.unpack('Q', lcnmft))
		print "Logical Cluster Number Mirror MFT: %s" % (struct.unpack('Q', lcnmftMirr))

	impStuff = {}
	impStuff['mft'] = struct.unpack('Q', lcnmft)[0]*clusterSize
	impStuff['mftmirror'] = struct.unpack('Q', lcnmftMirr)[0]*clusterSize
	impStuff['clustersize'] = clusterSize
	impStuff['bytespersector'] = struct.unpack('H', bytesPerSector)[0]
	impStuff['sectorsize'] = args.sectorsize
	impStuff['psize'] = p['size']

	return impStuff, fp

############################################################################

def partitionEntry(args, part):
	"""
	examine a partition entry
	"""
	if args.part:
		print
	partition = {}
	active = part[0]
	if active == '\x80':
		if args.part:
			print "boot partition"
		partition['boot'] = True
	else:
		if args.part:
			print "non-boot partition"
		partition['boot'] = False

	head = part[1]
	sector = part[2]
	cylinder = part[3]

	if args.part:
		print "First Sector in Partition -> Head: %s Sector: %s Cylinder: %s" % (struct.unpack('B',head)[0], struct.unpack('B',sector)[0], struct.unpack('B',cylinder)[0])

	types = {}
	types['0x0'] = "Empty partition"
	types['0x5'] = "Extended partition"
	types['0x7'] = "Microsoft NTFS"
	types['0x82'] = "Linux Swap"
	types['0x83'] = "Linux Native"
	types['0x8e'] = "Linux LVM"
	types['0xaf'] = "Apple Mac OS X HFS and HFS+"
	types['0xee'] = "EFI protective MBR"

	partType = struct.unpack('B',part[4])[0]
	if args.part:
		print "Partition Type: %s (%s)" % (hex(partType), types[hex(partType)])
	partition['type'] = types[hex(partType)]

	shead = part[5]
	ssector = part[6]
	scyl = part[7]
	if args.part:
		print "Last Sector in Partition -> Head: %s Sector: %s Cylinder: %s" % (struct.unpack('B',shead)[0], struct.unpack('B',ssector)[0], struct.unpack('B',scyl)[0])

	firstSec = struct.unpack('I',part[8:12])[0]
	numSecs = struct.unpack('I',part[12:16])[0]
	psize = numSecs*512

	if args.part:
		print "LBA of first Sector: %s" % (firstSec)
		print "Number of Sectors: %s" % (numSecs)
		print "Partition Size: %s" % (psize)

	partition['lbafirstsector'] = firstSec
	partition['numsectors'] = numSecs
	partition['size'] = psize
	return partition

############################################################################

def readMBR(args, fp):
	"""
	read the MBR of a device
	"""
	mbr = fp.read(512)

	if args.mbr:
		print "=== Master Boot Record ==="

	bootloader = mbr[0:440]
	disksignature = mbr[440:444]
	null = mbr[444:446]
	partitiontable = mbr[446:510]
	mbrsigend = mbr[510:]

	if args.mbr:
		print "Disksignature: %s" % (hex(struct.unpack('I', disksignature)[0]))
	#print [partitiontable], len(partitiontable)
	part1 = partitiontable[0:16]
	part2 = partitiontable[16:32]
	part3 = partitiontable[32:48]
	part4 = partitiontable[48:64]

	if args.part:
		print "=== Partition Table ==="
	parts = []
	parts.append(partitionEntry(args, part1))
	parts.append(partitionEntry(args, part2))
	parts.append(partitionEntry(args, part3))
	parts.append(partitionEntry(args, part4))
	if args.part:
		print
	return parts

############################################################################

if __name__ == '__main__':
	### parse command-line arguments
	parser = argparse.ArgumentParser(prog='NTFS Parser', description='Parse MBR, read Partitions, and display MFT entries of NTFS Partitions')
	parser.add_argument('device', metavar='DEVICE', type=str, help='a device to investigate (/dev/sda)')
	parser.add_argument('--vmdk', help='device is sparse vmdk file', action='store_true')
	parser.add_argument('--mbr', help='display MBR', action='store_true')
	parser.add_argument('--part', help='display Partitions', action='store_true')
	parser.add_argument('--boot', help='display Boot Sectors', action='store_true')
	parser.add_argument('--mft', help='display MFT entries', action='store_true')
	parser.add_argument('--brute', help='search for MFT entries by signature (slow)', action='store_true')
	parser.add_argument('--sectorsize', help='specify sector size (default: try to read from partition information)', type=int)
	args = parser.parse_args()
	### open device
	fp = open(args.device, 'r')

        if args.vmdk:
                print "=== Try to read VMDK file ==="
                ### check if splitted files or not
                if fp.read(21) == '# Disk DescriptorFile':
                        bn = os.path.dirname(os.path.abspath(args.device))
                        print "== Found VMDK descriptor file, try to get splitted disk files"
                        fileLst = []
                        for rline in fp.readlines():
                                line = rline.strip()
                                if line.count('RW')>0 and line.count('SPARSE')>0:
                                        diskname = line.rsplit('SPARSE', 1)[1].strip()
                                        diskname = os.path.join(bn, diskname.replace('"',''))
                                        fileLst.append(diskname)
                        fp.close()
                        for dev in fileLst:
                                print "=== opening: %s" % dev
                                fp = open(dev, 'r')
                                if not args.sectorsize:
                                        sectorSize = 512
                                else:
                                        sectorSize = args.sectorsize
                                statinfo = os.stat(dev)
                                partStuff = {'mft': 512, 'sectorsize': sectorSize, 'psize': statinfo.st_size}
                                fp.seek(0, 0)
                                if args.mft:
                                        examineMFT(args, partStuff, fp)
                                fp.close()
                else:
                        ### try to locate MBR of VMDK file (not required)
                        #fp.seek(56, 0)
                        #gdOffset = int(struct.unpack('Q', fp.read(8))[0])*512
                        #fp.seek(gdOffset, 0)
                        #metaOffset = int(struct.unpack('I', fp.read(4))[0])*512
                        #fp.seek(metaOffset, 0)
                        #mbrOffset = int(struct.unpack('I', fp.read(4))[0])*512
                        #if mbrOffset > 0:
                        #        fp.seek(mbrOffset, 0)
                        #        parts = readMBR(args, fp)
                        if not args.sectorsize:
                                sectorSize = 512
                        else:
                                sectorSize = args.sectorsize
                        ### get file size
                        statinfo = os.stat(args.device)
                        partStuff = {'mft': 512, 'sectorsize': sectorSize, 'psize': statinfo.st_size}
                        fp.seek(0, 0)
                        if args.mft:
                                if args.brute:
                                        bruteMFT(partStuff, fp)
                                else:
                                        examineMFT(args, partStuff, fp)
        else:
                ### read Master Boot Record
                parts = readMBR(args, fp)

                if args.boot:
                    print
                    print "=== Partitions ==="

                for p in parts:
                        if p['type'] == 'Microsoft NTFS':
                                partStuff, fp = examineNTFS(args, p, fp)
                                if args.mft:
                                        examineMFT(args, partStuff, fp)
	fp.close()


