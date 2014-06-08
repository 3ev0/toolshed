"""
The android boot image file (usually boot.img) is has a file format specifically used by Android bootloaders.
The file format is as follows:

/*
** +-----------------+
** | boot header     | 1 page
** +-----------------+
** | kernel          | n pages
** +-----------------+
** | ramdisk         | m pages
** +-----------------+
** | second stage    | o pages
** +-----------------+
**
** n = (kernel_size + page_size - 1) / page_size
** m = (ramdisk_size + page_size - 1) / page_size
** o = (second_size + page_size - 1) / page_size
**
** 0. all entities are page_size aligned in flash
** 1. kernel and ramdisk are required (size != 0)
** 2. second is optional (second_size == 0 -> no second)
** 3. load each element (kernel, ramdisk, second) at
**    the specified physical address (kernel_addr, etc)
** 4. prepare tags at tag_addr.  kernel_args[] is
**    appended to the kernel commandline in the tags.
** 5. r0 = 0, r1 = MACHINE_TYPE, r2 = tags_addr
** 6. if second_size != 0: jump to second_addr
**    else: jump to kernel_addr
*/

Kernel is a zimage file.
Ramdisk is the initramfs file, which is a gzipped cpio archive containing the dir tree that is mounted at '/'
by the boot loader.

"""
__author__ = 'ivo'

import struct
import io
import logging
import gzip
import subprocess
import os.path
import os
import tempfile

_log = logging.getLogger(__name__)

class BootImgHeader():
    _struct = "<8sIIIIIIII4x4x16s512s32s1024s"
    structlen = struct.calcsize(_struct)

    @classmethod
    def fromBytes(cls, blob):
        bih = cls()
        (bih.magic, bih.kernel_size, bih.kernel_addr,
         bih.ramdisk_size, bih.ramdisk_addr, bih.second_size,
         bih.second_addr, bih.tags_addr, bih.page_size,
         bih.name, bih.cmdline, bih.id, bih.extra_cmdline) = struct.unpack_from(cls._struct, blob)
        return bih

    @classmethod
    def fromFile(cls, fh):
        return cls.fromBytes(fh.read(cls.structlen))

    def __repr__(self):
        return "<{}({})>".format(self.__class__.__name__, vars(self))

def _extract_kernel(fh):
    hdr = BootImgHeader.fromFile(fh)
    fh.seek(hdr.page_size - BootImgHeader.structlen, io.SEEK_CUR)
    kernel_blob = fh.read(hdr.kernel_size)
    return kernel_blob

def extract_kernel(fh):
    if isinstance(fh, str):
        with open(fh, "rb") as fh:
            return _extract_kernel(fh)
    else:
        return _extract_kernel(fh)

def _extract_ramdisk(fh):
    hdr = BootImgHeader.fromFile(fh)
    fh.seek(hdr.page_size - BootImgHeader.structlen, io.SEEK_CUR)
    fh.seek(hdr.kernel_size, io.SEEK_CUR)
    fh.seek(hdr.page_size - (hdr.kernel_size % hdr.page_size), io.SEEK_CUR)
    ramdisk_blob = fh.read(hdr.ramdisk_size)
    return ramdisk_blob

def extract_ramdisk(fh):
    if isinstance(fh, str):
        with open(fh, "rb") as fh:
            return _extract_ramdisk(fh)
    else:
        return _extract_ramdisk(fh)

def unpack_ramdisk(blob, destdir):
    extractdir = os.path.join(destdir, "ramdisk_unpacked")
    if not os.path.exists(extractdir):
        os.mkdir(extractdir)
    _log.info("Unpacking ramdisk to %s...", extractdir)

    tfh = tempfile.TemporaryFile()
    with gzip.open(io.BytesIO(blob), "rb") as gfh:
            tfh.write(gfh.read())
    tfh.seek(0)
    subprocess.check_call(["cpio", "-i", "--no-absolute-filenames"], stdin=tfh, cwd=extractdir)
    return extractdir
