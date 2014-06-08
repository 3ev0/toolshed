__author__ = 'ivo'

import os
import struct
import subprocess
import logging

_log = logging.getLogger(__name__)

def fstype(filepath):
    if is_yaffs_image(filepath):
        return "yaffs"
    elif is_ext4(filepath):
        return "ext4"
    elif is_sparseext4(filepath):
        return "sparse"
    else:
        return None

def is_boot_image(filepath):
    """
    Android boot image is not really a file system. It contains a gzipped linux kernel and ramdisk.
    The file starts with a 2k header.
    From bootimg.h:

    #define BOOT_MAGIC "ANDROID!"
    struct boot_img_hdr
    {
        unsigned char magic[BOOT_MAGIC_SIZE];

        ...
    };

    :param filepath:
    :return:True or false
    """
    if not os.path.isfile(filepath):
        return False
    try:
        headerbytes = open(filepath, "br").read(2048)
        (magic,) = struct.unpack("8s2040x", headerbytes)
        return magic == b"ANDROID!"
    except struct.error:
        return False

def is_bootloader_image(filepath):
    """
    Is this file an android AOSP bootloader file?
    Bootloader files not from Nexus devices will probably not be detected by this algorithm.
    :param filepath:
    :return:True or false
    """
    if not os.path.isfile(filepath):
        return False
    try:
        headerbytes = open(filepath, "br").read(2048)
        (magic,) = struct.unpack("8s2040x", headerbytes)
        return magic == b"BOOTLDR!"
    except struct.error:
        return False

def is_yaffs_image(filepath):
    """
    According to yaffs2 yaffs_guts.c source code:
    struct yaffs_obj_hdr {
        enum yaffs_obj_type type; <-- This can be an int value between 0 and 4 (likely 3)
        int parent_obj_id; <-- Usually 1, but not sure enough to use
        u16 sum_no_longer_used;	/* checksum of name. No longer used */ <-- this is set to 0xFFFF
    """
    if not os.path.isfile(filepath):
        return False
    try:
        headerbytes = open(filepath, "br").read(10)
        (parent_obj_id, sum_no_longer_used) = struct.unpack("I4x2s", headerbytes)
        #_log.debug("%d, %s", parent_obj_id, sum_no_longer_used)
        return (parent_obj_id in range(0,5) and sum_no_longer_used == b"\xFF\xFF")
    except struct.error:
        return False

def is_sparseext4(filepath):
    """
    From ext4_utils/sparse_format.h:
    typedef struct sparse_header {
      __le32    magic;      /* 0xed26ff3a */
      __le16    major_version;  /* (0x1) - reject images with higher major versions */
      __le16    minor_version;  /* (0x0) - allow images with higer minor versions */
      __le16    file_hdr_sz;    /* 28 bytes for first revision of the file format */
      __le16    chunk_hdr_sz;   /* 12 bytes for first revision of the file format */
      __le32    blk_sz;     /* block size in bytes, must be a multiple of 4 (4096) */
      __le32    total_blks; /* total blocks in the non-sparse output image */
      __le32    total_chunks;   /* total chunks in the sparse input image */
      __le32    image_checksum; /* CRC32 checksum of the original data, counting "don't care" */
                    /* as 0. Standard 802.3 polynomial, use a Public Domain */
                    /* table implementation */
    } sparse_header_t;

    #define SPARSE_HEADER_MAGIC 0xed26ff3a
    """
    try:
        headerbytes = open(filepath, "br").read(4)
        (magic,) = struct.unpack("I", headerbytes)
        return magic == 0xed26ff3a
    except struct.error:
        return False

def is_ext4(filepath):
    """
    Determine if the file is an ext4 image file.
    First 1024 bytes of file are padding. Then superblock. In superblock at offset 0x38 there should be 2-byte magic
    value of 0xEF53.
    :param filepath: The file to check
    :return:true or false
    """
    try:
        headerbytes = open(filepath, "br").read(4)
        (m,) = struct.unpack("1024x62c2c", headerbytes)
        return m == b"\xed\x26\xff\x3a"
    except struct.error:
        return False

def unpack_yaffs(imagepath, destdir):
    """
    Unpack yaffs2 image to a directory. A subdirectory with the same name as the file name is created in destdir.
    :param imagepath: Path to yaffs2 image file
    :param destdir: Directory to create mountdir in
    :return:the actual mount directory
    """
    _log.info("Extracting Yaffs2 image...")
    fn = os.path.basename(imagepath)
    extractdir = os.path.join(destdir, fn)
    if os.path.exists(extractdir):
        if len(os.listdir(extractdir)):
            _log.error("Extract dir %s exists and is not empty", extractdir)
            raise Exception("extractdir exists")
        else:
            os.rmdir(extractdir)
    os.makedirs(extractdir)
    subprocess.check_call(["unyaffs", imagepath, extractdir])
    _log.info("Image extracted to %s", extractdir)
    return extractdir

def mount_image(imagepath, destdir):
    """
    Mount a file system image. A subdirectory with the same name as the file name is created in destdir.
    The image is mounted using the linux mount command. It relies on the automatic file system detection of mount.
    :param imagepath: Path to file system image file
    :param destdir: Directory to create mountdir in
    :return:The actual mount directory
    """
    fn = os.path.basename(imagepath)
    mountdir = os.path.join(destdir, fn)
    if os.path.exists(mountdir):
        if len(os.listdir(mountdir)):
            _log.error("Mountdir %s exists and is not empty", mountdir)
            raise Exception("Mountdir exists")
        else:
            os.rmdir(mountdir)
    os.makedirs(mountdir)
    subprocess.check_call(["sudo", "mount",imagepath, mountdir, "-o", "ro"])
    _log.info("%s mounted", imagepath)
    return mountdir

def unmount_image(path):
    subprocess.check_call(["sudo", "umount", path])
    _log.info("%s unmounted", path)