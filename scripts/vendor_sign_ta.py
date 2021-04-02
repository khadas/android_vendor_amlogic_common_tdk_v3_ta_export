#!/usr/bin/env python
#
# Copyright (C) 2016 Amlogic, Inc. All rights reserved.
#
#
# This source code is subject to the terms and conditions defined in the
# file 'LICENSE' which is part of this source code package.
#
#

def get_args():
	from argparse import ArgumentParser

	parser = ArgumentParser()
	parser.add_argument('--ta_rsa_key', dest = 'ta_prv_key', required = True, \
			help = 'ta rsa private key, input file')
	parser.add_argument('--ta_rsa_key_sig', dest = 'cert_sig', required = True, \
			help = 'signature of ta cert header and ta pub key, input file')
	parser.add_argument('--in', dest = 'ta', required = True, \
			help = 'input ta file')
	parser.add_argument('--out', dest = 'signed_ta', default = 'null', \
			help = 'output signed ta file')

	return parser.parse_args()

def is_signed_ta(ta):
	import struct

	with open(ta, 'rb') as f:
		__magic, __version, __flags, __algo, \
		__arb_cvn, __img_type, __img_size, __enc_type, \
		__arb_type = struct.unpack('<9I', f.read(36))
		if __img_type == 2:
			return True
		else:
			return False

	ta_hdr_size = 128
	ta_payload_digest_size = 32

	with open(ta, 'rb') as f:
		f.seek(20)
		type = f.read(4)
		img_type = struct.unpack('<I', type)[0]

		if img_type != 2:
			return False

		f.seek(ta_hdr_size + ta_payload_digest_size)
		magic = struct.unpack('<I', f.read(4))[0]

		if magic != 0x43455254:
			return False

		return True

def is_double_signed_ta(ta):
	import struct

	ta_hdr_size = 128
	ta_payload_digest_size = 32
	ta_cert_hdr_size = 64
	ta_pub_key_size = 256
	ta_cert_sig_size = 256
	ta_payload_sig_size = 256

	with open(ta, 'rb') as f:
		f.seek(ta_hdr_size + ta_payload_digest_size + ta_cert_hdr_size + ta_pub_key_size + ta_cert_sig_size + ta_payload_sig_size)
		magic = struct.unpack('<I', f.read(4))[0]

		if magic != 0x43455254:
			return False

		return True

class ta_cert_hdr():
	def __init__(self, ta_uuid):
		import uuid

		ta_uuid_str = "{" + ta_uuid + "}"
		self.__magic = 0x43455254        # header magic, value = "CERT"
		self.__version = 0x00000100      # cert version, 1.0
		self.__uuid = uuid.UUID(ta_uuid_str).bytes_le  # 16bytes uuid
		self.__rsv = [0] *  10           # 36bytes reserved

	def serialize(self):
		import struct
		return struct.pack('<2I', self.__magic, self.__version) + \
				self.__uuid + struct.pack('<10I', *self.__rsv)

def main():
	import sys
	import struct
	from Crypto.Hash import SHA256
	from Crypto.PublicKey import RSA
	from Crypto.Signature import PKCS1_v1_5
	from Crypto.Util.number import long_to_bytes

	args = get_args()

	ta_hdr_size = 128
	ta_payload_digest_size = 32
	ta_cert_hdr_size = 64
	ta_pub_key_size = 256
	ta_cert_sig_size = 256
	ta_payload_sig_size = 256

	if is_signed_ta(args.ta) == False:
		print 'Not a valid signed TA'
		sys.exit(0)

	if is_double_signed_ta(args.ta) == True:
		print 'double signed TA already'
		sys.exit(0)

	if args.signed_ta == 'null':
		args.signed_ta = args.ta

	with open(args.ta_prv_key, 'rb') as ta_priv_key_f,\
		open(args.cert_sig, 'rb') as ta_cert_sig_f,\
		open(args.ta, 'rb') as ta_f,\
		open(args.signed_ta, 'wb') as signed_ta_f:

		ta_prv_key = RSA.importKey(ta_priv_key_f.read())
		ta_pub_key = long_to_bytes(ta_prv_key.publickey().n)

		ta_cert_sig = ta_cert_sig_f.read()

		sha256 = SHA256.new()
		sha256.update(ta_f.read(ta_hdr_size + ta_payload_digest_size))
		ta_payload_sig = PKCS1_v1_5.new(ta_prv_key).sign(sha256)

		ta_f.seek(0);
		signed_ta_f.write(ta_f.read(ta_hdr_size + ta_payload_digest_size\
					+ ta_cert_hdr_size + ta_pub_key_size\
					+ ta_cert_sig_size + ta_payload_sig_size))

		uuid = "" + args.ta.split('/')[-1]
		uuid = uuid[:-3]

		ta_cert_h = ta_cert_hdr(uuid)
		signed_ta_f.write(ta_cert_h.serialize())
		signed_ta_f.write(ta_pub_key)
		signed_ta_f.write(ta_cert_sig)
		signed_ta_f.write(ta_payload_sig)

		signed_ta_f.write(ta_f.read())

	print 'Signing TA ...'
	print '  Input:'
	print '                  ta_prv_key.name = ' + args.ta_prv_key
	print '                  ta_prv_key.size = {}'.format(ta_prv_key.size() + 1)
	print '                    cert_sig.name = ' + args.cert_sig
	print '                          ta.name = ' + args.ta
	print '  Output:          signed_ta.name = ' + args.signed_ta

if __name__ == "__main__":
	main()
