#!/usr/bin/env python3
#
# Copyright (C) 2016 Amlogic, Inc. All rights reserved.
#
#
# This source code is subject to the terms and conditions defined in the
# file 'LICENSE' which is part of this source code package.
#

def get_args():
	from argparse import ArgumentParser

	parser = ArgumentParser()
	parser.add_argument('--rsk', default='null', help='root signing key')
	parser.add_argument('--rek', default='null', help='root encrypt key')
	parser.add_argument('--dev-rsk', default='null', help='root signing key(dev)')
	parser.add_argument('--dev-rek', default='null', help='root encrypt key(dev)')
	parser.add_argument('--cas-rsk', default='null', help='root signing key(cas)')
	parser.add_argument('--cas-rek', default='null', help='root encrypt key(cas)')
	parser.add_argument('--cas-uuid', default='null', help='cas ta uuid list')
	parser.add_argument('--pcpk', default='null', help='provision common protect key')
	parser.add_argument('--arb', default='null', help='TA antirollback table file')
	parser.add_argument('--perm', default='null', help='TA Permission file')
	parser.add_argument('--dts', default='null', help='output dts file')
	parser.add_argument('--in', dest='inf', default='null', help='input Secure OS image file')
	parser.add_argument('--out', type=str, default='null', help='output Secure OS image file')
	return parser.parse_args()

def read_rsk(rsk):
	from Cryptodome.PublicKey import RSA

	with open(rsk, 'rb+') as f:
		return RSA.importKey(f.read())

def read_key(key):
	with open(key, 'rb+') as f:
		return f.read()

def cas_uuid_check(infile):
	import uuid

	tmp = []

	try:
		f = open(infile, 'r')
		lines = f.readlines()
	except:
		print ("Open File: %s fail!" %(infile))
		return False
	else:
		f.close

	for line in lines:
		line = line.strip()
		if not len(line) or line.startswith('#'):
			continue

		uuid_str = "{" + line + "}"
		try:
			ta_uuid = uuid.UUID(uuid_str)
		except:
			print ("Bad format UUID!")
			return False
		else:
			if ta_uuid in tmp:
				print ("Dumplicate UUID: ",)
				print (ta_uuid)
				return False
			tmp.append(ta_uuid)

	return True

def cas_uuid_parser(infile, outfile):
	import struct
	import uuid
	import binascii

	count = 0

	try:
		f = open(infile, 'r')
		lines = f.readlines()
	except:
		print ("Open File: %s fail!" %(infile))
		return 0
	else:
		f.close

	try:
		f = open(outfile, 'wb+')
	except:
		print ("Open File: %s fail!" %(outfile))
		return 0

	for line in lines:
		line = line.strip()
		if not len(line) or line.startswith('#'):
			continue

		uuid_str = "{" + line + "}"
		try:
			ta_uuid = uuid.UUID(uuid_str)
		except:
			print ("Bad format UUID!")
			return 0
		else:
			ta_uuid_hex = binascii.hexlify(ta_uuid.bytes_le)
			ta_uuid_bin = binascii.a2b_hex(ta_uuid_hex)

		f.write(ta_uuid_bin)
		count += 1

	f.close()

	return count

def ta_antirollback_table_check(infile):
	import uuid

	tmp = []

	try:
		f = open(infile, 'r')
		lines = f.readlines()
	except:
		print ("Open File: %s fail!" %(infile))
		return False
	else:
		f.close

	for line in lines:
		line = line.strip()
		if not len(line) or line.startswith('#'):
			continue

		uuid_str = "{" + line.split(':')[0].strip() + "}"
		try:
			ta_uuid = uuid.UUID(uuid_str)
		except:
			print ("Bad format UUID!")
			return False
		else:
			if ta_uuid in tmp:
				print ("Dumplicate UUID: ",)
				print (ta_uuid)
				return False
			tmp.append(ta_uuid)

	return True

def ta_antirollback_table_parser(infile, outfile):
	import struct
	import uuid
	import binascii

	count = 0

	try:
		f = open(infile, 'r')
		lines = f.readlines()
	except:
		print ("Open File: %s fail!" %(infile))
		return 0
	else:
		f.close

	try:
		f = open(outfile, 'wb+')
	except:
		print ("Open File: %s fail!" %(outfile))
		return 0

	for line in lines:
		line = line.strip()
		if not len(line) or line.startswith('#'):
			continue

		uuid_str = "{" + line.split(':')[0].strip() + "}"
		try:
			ta_uuid = uuid.UUID(uuid_str)
		except:
			print ("Bad format UUID!")
			return 0
		else:
			ta_uuid_hex = binascii.hexlify(ta_uuid.bytes_le)
			ta_uuid_bin = binascii.a2b_hex(ta_uuid_hex)

		try:
			ta_ver_str = line.split(':')[1]
			ta_ver = int(ta_ver_str)
		except:
			print ("Bad format TA version!")
			return 0
		else:
			ta_ver = struct.pack('<I', ta_ver)

		f.write(ta_uuid_bin)
		f.write(ta_ver)
		count += 1

	f.close()

	return count

def ta_perm_table_parser(infile, outfile):
	import struct
	import uuid
	import binascii
	import configparser

	count = 0

	with open(infile, 'r') as inf, open(outfile, 'wb+') as ouf:
		lines = inf.readlines()

		for line in lines:
			line = line.strip()
			if not len(line) or line.startswith('#') or line.startswith('[permission]'):
				continue

			uuid_str = "{" + line.split('=')[1].strip() + "}"
			try:
				ta_uuid = uuid.UUID(uuid_str)
			except:
				print ("Bad format UUID!")
				return 0
			else:
				ta_uuid_hex = binascii.hexlify(ta_uuid.bytes_le)
				ta_uuid_bin = binascii.a2b_hex(ta_uuid_hex)

			ouf.write(struct.pack('<I', int(line.split('=')[0].strip(), 16)))
			ouf.write(ta_uuid_bin)
			count += 1

	return count

def main():
	import struct
	import array
	import base64
	import os
	from Cryptodome.PublicKey import RSA
	from Cryptodome.Util.number import long_to_bytes
	from pyfdt.pyfdt import Fdt, FdtNode, FdtPropertyStrings, FdtPropertyWords

	tmpfile = ".tmp"

	args = get_args()
	if args.out == 'null':
		args.out = args.inf

	root = FdtNode("/")
	root.add_subnode(FdtPropertyStrings("model", ["amlogic"]))
	root.add_subnode(FdtPropertyStrings("compatible", ["amlogic, TEE"]))

	# root keys
	if args.rsk != 'null' or args.rek != 'null' or args.pcpk != 'null' or\
		       args.dev_rsk != 'null' or args.dev_rek != 'null':
		keys = FdtNode("keys")
		keys.set_parent_node(root)
		root.add_subnode(keys)
		keys.add_subnode(FdtPropertyStrings("compatible", ["amlogic, tee keys"]))

	if args.rsk != 'null':
		with open(args.rsk, 'rb+') as f:
			rsk = RSA.importKey(f.read())
			rsk_size = rsk.size_in_bytes()
			rsk_b64 = base64.b64encode(long_to_bytes(rsk.publickey().n))

		keys.add_subnode(FdtPropertyStrings("rsk", [bytes.decode(rsk_b64)]))
		keys.add_subnode(FdtPropertyWords("rsk_size", [rsk_size]))

	if args.rek != 'null':
		if args.rsk == 'null':
			print ("rsk is a must when rek is provided")
			exit(-1)

		with open(args.rek, 'rb+') as f:
			rek = f.read()
			rek_size = len(rek)
			rek_b64 = base64.b64encode(rek)

		keys.add_subnode(FdtPropertyStrings("rek", [bytes.decode(rek_b64)]))
		keys.add_subnode(FdtPropertyWords("rek_size", [rek_size]))

	if args.pcpk != 'null':
		with open(args.pcpk, 'rb+') as f:
			pcpk = f.read()
			pcpk_size = len(pcpk)
			pcpk_b64 = base64.b64encode(pcpk)

		keys.add_subnode(FdtPropertyStrings("pcpk", [bytes.decode(pcpk_b64)]))
		keys.add_subnode(FdtPropertyWords("pcpk_size", [pcpk_size]))

	if args.dev_rsk != 'null':
		with open(args.dev_rsk, 'rb+') as f:
			rsk = RSA.importKey(f.read())
			rsk_size = rsk.size_in_bytes()
			rsk_b64 = base64.b64encode(long_to_bytes(rsk.publickey().n))

		keys.add_subnode(FdtPropertyStrings("dev_rsk", [bytes.decode(rsk_b64)]))
		keys.add_subnode(FdtPropertyWords("dev_rsk_size", [rsk_size]))

	if args.dev_rek != 'null':
		if args.dev_rsk == 'null':
			print ("rsk is a must when rek is provided")
			exit(-1)

		with open(args.dev_rek, 'rb+') as f:
			rek = f.read()
			rek_size = len(rek)
			rek_b64 = base64.b64encode(rek)

		keys.add_subnode(FdtPropertyStrings("dev_rek", [bytes.decode(rek_b64)]))
		keys.add_subnode(FdtPropertyWords("dev_rek_size", [rek_size]))

	# cas keys and TA uuids
	if args.cas_rsk != 'null' or args.cas_rek != 'null':
		if args.cas_uuid == 'null':
			print ("cas keys provide, but cas TA UUID not provide!")
			exit(-1)

		cas = FdtNode("cas")
		cas.set_parent_node(root)
		root.add_subnode(cas)
		cas.add_subnode(FdtPropertyStrings("compatible", ["amlogic, tee cas"]))

	if args.cas_rsk != 'null':
		with open(args.cas_rsk, 'rb+') as f:
			rsk = RSA.importKey(f.read())
			rsk_size = rsk.size_in_bytes()
			rsk_b64 = base64.b64encode(long_to_bytes(rsk.publickey().n))

		cas.add_subnode(FdtPropertyStrings("rsk", [bytes.decode(rsk_b64)]))
		cas.add_subnode(FdtPropertyWords("rsk_size", [rsk_size]))

	if args.cas_rek != 'null':
		if args.cas_rsk == 'null':
			print ("rsk is a must when rek is provided")
			exit(-1)

		with open(args.cas_rek, 'rb+') as f:
			rek = f.read()
			rek_size = len(rek)
			rek_b64 = base64.b64encode(rek)

		cas.add_subnode(FdtPropertyStrings("rek", [bytes.decode(rek_b64)]))
		cas.add_subnode(FdtPropertyWords("rek_size", [rek_size]))

	if args.cas_uuid != 'null':
		cas_uuid_num_max = 32
		if not cas_uuid_check(args.cas_uuid):
			print ("BAD TA UUID format!")
			exit(-1)

		count = cas_uuid_parser(args.cas_uuid, tmpfile)
		if not count:
			print ("No valid TA UUID in %sl!" %(args.cas_uuid))
			exit(-1)
		if count > cas_uuid_num_max:
			print ("TA UUID size(%d) exceed(max is %d)!" %(count, cas_uuid_num_max))
			exit(-1)

		with open(tmpfile, 'rb+') as f:
			cas_uuid_config = f.read()
		os.remove(tmpfile)
		cas_uuid_b64 = base64.b64encode(cas_uuid_config)

		cas.add_subnode(FdtPropertyStrings("uuids", [bytes.decode(cas_uuid_b64)]))
		cas.add_subnode(FdtPropertyWords("uuids_count", [count]))

	# antirollback table
	if args.arb != 'null':
		arb_table_len_max = 32
		if not ta_antirollback_table_check(args.arb):
			print ("BAD TA antirollback table format!")
			exit(-1)

		count = ta_antirollback_table_parser(args.arb, tmpfile)
		if not count:
			print ("No valid entry in TA antirollback table!")
			exit(-1)
		if count > arb_table_len_max:
			print ("TA antirollback table size(%d) exceed(max is %d)!" %(count, arb_table_len_max))
			exit(-1)

		with open(tmpfile, 'rb+') as f:
			arb_config = f.read()
		os.remove(tmpfile)
		arb_b64 = base64.b64encode(arb_config)

		arb = FdtNode("antirollback")
		arb.set_parent_node(root)
		root.add_subnode(arb)
		arb.add_subnode(FdtPropertyStrings("compatible", ["amlogic, tee arb"]))
		arb.add_subnode(FdtPropertyStrings("arb", [bytes.decode(arb_b64)]))
		arb.add_subnode(FdtPropertyWords("count", [count]))

	# permission table
	if args.perm != 'null':
		perm_table_len_max = 100
		count = ta_perm_table_parser(args.perm, tmpfile)
		if not count:
			exit(-1)
		if count > perm_table_len_max:
			print ("TA permission table size(%d) exceed(max is %d)!" %(count, perm_table_len_max))
			exit(-1)
		with open(tmpfile, 'rb+') as f:
			perm_config = f.read()
		os.remove(tmpfile)
		perm_b64 = base64.b64encode(perm_config)

		perm = FdtNode("permissions")
		perm.set_parent_node(root)
		root.add_subnode(perm)
		perm.add_subnode(FdtPropertyStrings("compatible", ["amlogic, tee perm"]))
		perm.add_subnode(FdtPropertyStrings("perm", [bytes.decode(perm_b64)]))
		perm.add_subnode(FdtPropertyWords("count", [count]))

	fdt = Fdt()
	fdt.add_rootnode(root)

	if args.dts != 'null':
		print ('Generating dts file...')

		with open(args.dts, 'wb+') as f:
			f.write(fdt.to_dts().encode())

	if args.out != 'null':
		dtb_header_len = 32
		dtb_len_max = 12 * 1024 - dtb_header_len
		dtb_len = len(fdt.to_dtb())
		if dtb_len > dtb_len_max:
			print ("dtb size(%d) exceed(max is %d)!" %(dtb_len, dtb_len_max))
			exit(-1)

		print ('Packing ...')
		if args.rsk != 'null':
			rsk_size = read_rsk(args.rsk).size_in_bits()
			print ('               rsk.name = ' + args.rsk)
			print ('               rsk.size = {}'.format(rsk_size))
		if args.rek != 'null':
			rek_size = len(read_key(args.rek))
			print ('               rek.name = ' + args.rek)
			print ('               rek.size = ' + str(rek_size))
		if args.pcpk != 'null':
			pcpk_size = len(read_key(args.pcpk))
			print ('               pcpk.name = ' + args.pcpk)
			print ('               pcpk.size = ' + str(pcpk_size))
		if args.dev_rsk != 'null':
			rsk_size = read_rsk(args.dev_rsk).size_in_bits()
			print ('           dev-rsk.name = ' + args.dev_rsk)
			print ('           dev-rsk.size = {}'.format(rsk_size))
		if args.dev_rek != 'null':
			rek_size = len(read_key(args.dev_rek))
			print ('           dev-rek.name = ' + args.dev_rek)
			print ('           dev-rek.size = ' + str(rek_size))
		if args.cas_rsk != 'null':
			rsk_size = read_rsk(args.cas_rsk).size_in_bits()
			print ('           cas-rsk.name = ' + args.cas_rsk)
			print ('           cas-rsk.size = {}'.format(rsk_size))
		if args.cas_rek != 'null':
			rek_size = len(read_key(args.cas_rek))
			print ('           cas-rek.name = ' + args.cas_rek)
			print ('           cas-rek.size = ' + str(rek_size))

		print ('             image.name = ' + args.inf)
		print ('    Output:  image.name = ' + args.out)

		with open(args.inf, 'rb+') as f:
			raw = f.read()

		with open(args.out, 'wb+') as f:
			f.write(raw)
			offs = raw.index(b"BTD@") + dtb_header_len
			f.seek(offs)
			f.write(fdt.to_dtb())

if __name__ == "__main__":
	main()
