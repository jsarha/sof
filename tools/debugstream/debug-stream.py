#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright (c) 2024, Intel Corporation.

import argparse
import mmap
import ctypes
import time
import sys

import logging
logging.basicConfig(format="%(filename)s:%(lineno)s %(funcName)s: %(message)s",
		    level=logging.WARNING)

DEBUG_STREAM_PAYLOAD_MAGIC = 0x1ED15EED

""" Generic Debug-stream header """
class DebugStreamHdr(ctypes.Structure):
	_fields_ = [
		("magic", ctypes.c_uint),
		("hdr_size", ctypes.c_uint),
	]

""" Debug Stream record for passing debug data """
class DebugStreamRecord(ctypes.Structure):
	_fields_ = [
		("id", ctypes.c_uint),
		("serial", ctypes.c_uint),
		("size", ctypes.c_uint),
	]

""" Thread Info record header """
class CPUInfo(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		("hdr", DebugStreamRecord),
		("load", ctypes.c_ubyte),
		("thread_count", ctypes.c_ubyte),
	]

""" Thread specific data-record, the thread name string starts after name_len """
class ThreadInfo(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		("stack_usage", ctypes.c_ubyte),
		("cpu_load", ctypes.c_ubyte),
		("name_len", ctypes.c_ubyte),
	]

WSIZE = ctypes.sizeof(ctypes.c_uint)

""" Debug Stream record decoder and printer class """
class RecordPrinter:
	RECORD_ID_UNINITIALIZED = 0
	RECORD_ID_THREAD_INFO = 1

	def print_record(self, record, cpu):
		recp = ctypes.cast(record, ctypes.POINTER(DebugStreamRecord))
		logging.debug(f"rec: {recp.contents.id} {recp.contents.serial} {recp.contents.size}")
		if recp.contents.id == self.RECORD_ID_THREAD_INFO:
			return self.print_thread_info(record, cpu)
		else:
			logging.warning(f"cpu {cpu}: Unsupported recodrd type {rec.contents.id}")
			return True

	def print_thread_info(self, record, cpu):
		remlen = len(record) - ctypes.sizeof(CPUInfo)
		if remlen < 0:
			logging.info(f"Buffer end reached, parsing failed")
			return False
		cpup = ctypes.cast(record, ctypes.
				   POINTER(CPUInfo))
		print("CPU %u: Load: %02.1f%% %u threads (serial %u)" %
		      (cpu, cpup.contents.load / 2.55,
		       cpup.contents.thread_count, cpup.contents.hdr.serial))
		remain = (ctypes.c_ubyte *
			   (len(record) - ctypes.sizeof(CPUInfo)
			    )).from_address(ctypes.addressof(record)
					    + ctypes.sizeof(CPUInfo))
		for i in range(cpup.contents.thread_count):
			remlen = remlen - ctypes.sizeof(ThreadInfo)
			if remlen < 0:
				logging.info(f"Buffer end reached, parsing failed")
				return False
			threadp = ctypes.cast(remain, ctypes.POINTER(ThreadInfo))
			remain = (ctypes.c_ubyte *
				  (len(remain) - ctypes.sizeof(ThreadInfo)
				   )).from_address(ctypes.addressof(remain)
						   + ctypes.sizeof(ThreadInfo))
			remlen = remlen - threadp.contents.name_len
			if remlen < 0:
				logging.info(f"Buffer end reached, parsing failed")
				return False
			name = bytearray(remain[:threadp.contents.name_len]).decode("utf-8")
			remain = (ctypes.c_ubyte *
				  (len(remain) - threadp.contents.name_len
				   )).from_address(ctypes.addressof(remain)
						   + threadp.contents.name_len)
			print("    %-20s stack %02.1f%%\tload %02.1f%%" %
			      (name, threadp.contents.stack_usage / 2.55,
			       threadp.contents.cpu_load / 2.55))
		return True

""" Describes CPU specific circular buffers """
class DebugStreamSectionDescriptor(ctypes.Structure):
	_fields_ = [
		("core_id", ctypes.c_uint),
		("buf_words", ctypes.c_uint),
		("offset", ctypes.c_uint),
		# This is for cacheline alignment
		("padding", ctypes.c_ubyte * (64 - 3 * WSIZE))
	]

""" Debug Slot transport specific Debug Stream header, padded to cache line """
class DebugStreamSlotHdr(ctypes.Structure):
	_fields_ = [
		("hdr", DebugStreamHdr),
		("total_size", ctypes.c_uint),
		("num_sections", ctypes.c_uint),
		# This is for cacheline alignment
		("padding", ctypes.c_ubyte * (64 - 2 * WSIZE -
					      ctypes.sizeof(DebugStreamHdr)))
	]

""" Live data header for CPU specific circular buffer """
class CircularBufHdr(ctypes.Structure):
	_fields_ = [
		("next_serial", ctypes.c_uint),
		("w_ptr", ctypes.c_uint),
	]

""" Class for extracting records from circular buffer """
class CircularBufferDecoder:
	desc = None
	boffset = None
	buf_words = None
	cpu = None
	printer = None
	prev_w_ptr = 0
	prev_serial = None
	error_count = 0
	def __init__(self, desc, cpu, printer):
		self.desc = desc
		self.boffset = desc.offset + ctypes.sizeof(CircularBufHdr)
		self.buf_words = desc.buf_words
		self.cpu = cpu
		self.printer = printer
		logging.debug(f"boffset {self.boffset} buf_words {self.buf_words} cpu {self.cpu}")

	def get_hdr(self, slot, pos):
		if pos >= self.buf_words:
			logging.warning(f"Bad position {pos}")
			return None
		hdr_size = ctypes.sizeof(DebugStreamRecord)
		hdr_words = hdr_size // WSIZE
		if pos + hdr_words > self.buf_words:
			hdr = (ctypes.c_ubyte * hdr_size)()
			size1 = (self.buf_words - pos) * WSIZE
			size2 = hdr_size - size1
			pos1 = self.boffset + pos * WSIZE
			pos2 = self.boffset
			logging.debug(f"Wrapped header {pos} {hdr_words} {self.buf_words} {size1}")

			hdr[0:size1] = slot[pos1:pos1 + size1]
			hdr[size1:hdr_size] = slot[pos2:pos2 + size2]
			header = ctypes.cast(hdr, ctypes.POINTER(DebugStreamRecord)).contents
		else:
			header = ctypes.cast(slot[self.boffset + pos * WSIZE:],
					     ctypes.POINTER(DebugStreamRecord)).contents
		if header.id > 100 or header.size >= self.buf_words:
			logging.warning(f"Broken record id {header.id} serial {header.serial} size {header.size}")
			return None
		return header

	def get_record(self, slot, pos, serial):
		rec = self.get_hdr(slot, pos)
		if rec == None or rec.size == 0:
			return None
		logging.debug(f"got header at pos {pos} rec {rec.id} {rec.serial} {rec.size}")
		if serial != None and rec.serial != serial:
			logging.warning(f"Record serial mismatch {rec.serial} != {serial}, pos {pos} size {rec.size}")
			self.error_count = self.error_count + 1
			return None
		rwords = rec.size
		rsize = rec.size * WSIZE
		if pos + rwords > self.buf_words:
			record = (ctypes.c_ubyte * rsize)()
			size1 = (self.buf_words - pos) * WSIZE
			size2 = rsize - size1
			pos1 = self.boffset + pos * WSIZE
			pos2 = self.boffset
			logging.debug(f"Wrapped record {pos} {rsize} {self.buf_words} {size1}")

			record[0:size1] = slot[pos1:pos1 + size1]
			record[size1:rsize] = slot[pos2:pos2 + size2]
		else:
			record = (ctypes.c_ubyte * rsize
				  ).from_buffer_copy(slot, self.boffset + pos * WSIZE)
		logging.info(f"got {rec.serial}")
		self.error_count = 0
		return record

	def catch_up(self, slot):
		circ = CircularBufHdr.from_buffer_copy(
			slot, self.desc.offset)
		if circ.next_serial == 0 or circ.w_ptr >= self.buf_words:
			return
		self.decode_past_records(slot, circ.w_ptr, circ.next_serial)
		self.prev_w_ptr = circ.w_ptr
		self.prev_serial = circ.next_serial - 1
		logging.info(f"serial {self.prev_serial} w_ptr {self.prev_w_ptr}")

	def decode_past_records(self, slot, pos, serial):
		if self.prev_serial != None and self.prev_serial >= serial - 1:
				return
		if pos == 0:
			spos = self.buf_words - 1
		else:
			spos = pos - 1
		bsize = ctypes.cast(slot[self.boffset + spos*4:],
				    ctypes.POINTER(ctypes.c_uint)).contents.value
		bpos = pos - bsize
		if bpos < 0:
			bpos = self.buf_words + pos - bsize
		rec = self.get_hdr(slot, bpos)
		if bsize != rec.size:
			return
		if serial != None:
			if rec.serial != serial - 1:
				return
		else:
			serial = rec.serial + 1

		self.decode_past_records(slot, bpos, serial - 1)

		record = self.get_record(slot, bpos, serial - 1)
		if record != None:
			if not self.printer.print_record(record, self.cpu):
				logging.info(f"Parse failed on record {serial - 1}")
			logging.info(f"Printing {serial - 1} success")
		else:
			logging.info(f"Broken record {serial - 1}")

	def get_next_record(self, slot):
		if self.prev_serial != None:
			record = self.get_record(slot, self.prev_w_ptr, self.prev_serial + 1)
		else:
			record = self.get_record(slot, self.prev_w_ptr, None)
		if record != None:
			success = self.printer.print_record(record, self.cpu)
			if success:
				recp = ctypes.cast(record, ctypes.POINTER(DebugStreamRecord))
				self.prev_w_ptr = (self.prev_w_ptr + recp.contents.size
						   ) % self.buf_words
				self.prev_serial = recp.contents.serial
			else:
				logging.info(f"Parse failed on record {self.prev_serial + 1}")
			return success
		self.error_count = self.error_count + 1
		logging.info(f"Record decoding failed {self.error_count}")
		return False

	def poll_buffer(self, slot):
		circ = CircularBufHdr.from_buffer_copy(
			slot, self.desc.offset)
		if self.prev_w_ptr == circ.w_ptr:
			return False
		success = True
		while self.prev_w_ptr != circ.w_ptr and success:
			success = self.get_next_record(slot)
		return True

	def check_error_count(self):
		if self.error_count > 3:
			return True
		return False

class DebugStreamDecoder:
	"""
	Class for finding thread analyzer chuck and initializing CoreData objects.
	"""
	file_size = 4096 # ADSP debug slot size
	f = None
	slot = None
	descs = []
	circdec = []
	rec_printer = RecordPrinter()

	def set_file(self, f):
		self.f = f

	def update_slot(self):
		self.f.seek(0)
		self.slot = self.f.read(self.file_size)

	def get_descriptors(self):
		if self.slot == None:
			return
		hdr = ctypes.cast(self.slot, ctypes.
				  POINTER(DebugStreamSlotHdr))
		if hdr.contents.hdr.magic != DEBUG_STREAM_PAYLOAD_MAGIC:
			logging.warning("Debug Slot has bad magic 0x%08x" %
					hdr.contents.hdr.magic)
			return False
		num_sections = hdr.contents.num_sections
		if num_sections == len(self.descs):
			return True
		hsize = ctypes.sizeof(DebugStreamSlotHdr)
		dsize = ctypes.sizeof(DebugStreamSectionDescriptor)
		self.descs = (DebugStreamSectionDescriptor * num_sections
			      ).from_buffer_copy(self.slot, hsize)
		self.circdec = [CircularBufferDecoder(self.descs[i], i,
						      self.rec_printer)
				for i in range(len(self.descs))]
		logging.info(f"Descriptors {hdr.contents.hdr.hdr_size} {hdr.contents.total_size} {hdr.contents.num_sections}")
		return True

	def catch_up_all(self):
		if len(self.descs) == 0 or self.slot == None:
			return
		for i in range(len(self.descs)):
			self.circdec[i].catch_up(self.slot)

	def poll(self):
		if len(self.descs) == 0 or self.slot == None:
			return
		sleep = True
		for i in range(len(self.descs)):
			if self.circdec[i].poll_buffer(self.slot):
				sleep = False
		return sleep

	def check_slot(self):
		hdr = ctypes.cast(self.slot, ctypes.
				  POINTER(DebugStreamSlotHdr))
		if hdr.contents.hdr.magic != DEBUG_STREAM_PAYLOAD_MAGIC:
			self.slot = None
			return False
		if hdr.contents.num_sections != len(self.descs):
			self.slot = None
			return False
		for i in range(len(self.descs)):
			if self.circdec[i].check_error_count():
				self.circdec[i] = CircularBufferDecoder(self.descs[i], i,
									self.rec_printer)
		return True

	def reset(self):
		self.f = None
		self.slot = None

def main_f(args):
	"""
	Open debug stream slot file and pass it to decoder
	"""
	decoder = DebugStreamDecoder()
	prev_error = None
	while True:
		try:
			with open(args.debugstream_file, "rb") as f:
				decoder.set_file(f)
				decoder.update_slot()
				if not decoder.get_descriptors():
					break
				decoder.catch_up_all()
				while True:
					if decoder.poll():
						time.sleep(args.update_interval)
					decoder.update_slot()
					if not decoder.check_slot():
						break

		except FileNotFoundError:
			print(f"File {args.debugstream_file} not found!")
			break
		except OSError as e:
			if str(e) != prev_error:
				print(f"Open {args.debugstream_file} failed '{e}'")
				prev_error = str(e)
		decoder.reset()
		time.sleep(args.update_interval)

def parse_params():
	""" Parses parameters
	"""
	parser = argparse.ArgumentParser(description=
					 "SOF DebugStream thread info client. ")
	parser.add_argument('-t', '--update-interval', type=float,
			    help='Telemetry2 window polling interval in seconds, default 1',
                            default=0.01)
	parser.add_argument('-f', '--debugstream-file',
			    help='File to read the DebugStream data from, default /sys/kernel/debug/sof/debug_stream',
                            default="/sys/kernel/debug/sof/debug_stream")
	parsed_args = parser.parse_args()
	return parsed_args

args = parse_params()
main_f(args)
