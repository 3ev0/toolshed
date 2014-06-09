__author__ = 'ivo'

"""
Script to build a hash list of files in AOSP Nexus Android file system images.
The file system images are downloaded from the AOSP internet sources. Each archive file is than unpacked and
all relevant images inside (system.img, boot.img, userdata.img, recovery.img) are mounted/unpacked and traversed.

The result is a leveldb database containing md5 hashes of all Nexus files.
This database can be used as an authenticated whitelist reference set to check encountered files for authenticity.

The script creates a meta db containing information on the processed sources. This can be used to verify from which sources
the hash values are generated.

"""


import requests
import re
import tempfile
import os.path
import shutil
import os
import logging
import tarfile
import zipfile
import argparse
import subprocess
import hashlib
import datetime
import json

from android import filesystem
from android import simg2img
from android import bootimg
from android import build_whitelist

import plyvel

_log = logging.getLogger()

TMPDIR = tempfile.gettempdir()

def md5file(fp):
    md5digest = hashlib.md5()
    with open(fp, "rb") as fh:
        blob = fh.read(1024*1024*16)
        while len(blob):
            md5digest.update(blob)
            blob = fh.read(1024*1024*16)
    return md5digest.hexdigest()

def scrape_links():
    """
    Scrape links to image archive from AOSP website
    :return: list with 3-tuple (source id, url, md5 string)
    """
    index_url = "https://developers.google.com/android/nexus/images"
    index_page = requests.get(index_url)
    results = re.findall("<tr id=\"(.*)\">\s*<td.*\s*<td><a href=\"(http.*\.tgz)\">Link</a>\s*<td>([a-f0-9A-F]{32})", index_page.text, flags=re.M)
    _log.info("Scraped %d links from %s", len(results), index_url)
    return results

def get_filename(url):
    return url.split("/")[-1]

def select_interesting(members):
    for tarinfo in members:
        if os.path.splitext(tarinfo.name)[1] == ".img" or os.path.splitext(tarinfo.name)[1] == ".zip":
            yield tarinfo

def untar_files(fp, destdir):
    """
    Untar all interesting files to destdir.
    :param fp: The tar or tgz file.
    :param destdir: The directory to unpack the files in
    """
    with tarfile.open(fp) as tar:
        members = select_interesting(tar)
        for member in members:
            fn = os.path.basename(member.name)
            destpath = os.path.join(destdir, fn)
            with tar.extractfile(member) as memberfh, open(destpath, "wb") as destfh:
                blob = memberfh.read(4096)
                while blob:
                    destfh.write(blob)
                    blob = memberfh.read(4096)
            _log.info("Extracted %s to %s", member.name, destpath)

def unzip_images(fp, destdir):
    with zipfile.ZipFile(fp) as zf:
        imagemembers = [im for im in zf.infolist() if os.path.splitext(im.filename)[-1] == ".img"]
        for member in imagemembers:
            fn = os.path.basename(member.filename)
            destpath = os.path.join(destdir, fn)
            if os.path.exists(destpath):
                _log.info("No need to unzip %s, it allready exists", member.filename)
                continue
            with zf.open(member, "r") as memberfh, open(destpath, "wb") as destfh:
                blob = memberfh.read(4096)
                while blob:
                    destfh.write(blob)
                    blob = memberfh.read(4096)
            _log.info("Unzipped %s to %s", member.filename, destpath)
    return len(imagemembers)

def build(hashdb, sourcesdb):
    sources = scrape_links()
    _log.info("Using %s as sources database", sourcesdb)
    for (source_id, source, md5val) in sources:
        _log.info("Processing %s...", source)
        fn = get_filename(source)
        fp = os.path.join(TMPDIR, fn)
        dbif = plyvel.DB(sourcesdb, create_if_missing=True)
        dbval = dbif.get(bytes(md5val, encoding="utf8"))
        dbif.close()
        if dbval:
            _log.info("Source found in sourcesdb: %s", str(dbval, encoding="utf8"))
            _log.info("Source processed!: %s", source)
            continue
        if not os.path.exists(fp):
            download = True
        else:
            _log.info("File %s allready present", fp)
            if md5val != md5file(fp):
                _log.info("Md5 does not match value on remote source, will download again")
                os.remove(fp)
                download = True
            else:
                _log.info("Md5 match, will skip download")
                download = False

        if download:
            r = requests.get(source, stream=True)
            with open(fp, 'wb') as fd:
                for chunk in r.iter_content(4096):
                    fd.write(chunk)
            _log.info("File downloaded to %s", fp)

        untardir = os.path.join(TMPDIR, os.path.splitext(fn)[0])
        if not os.path.isdir(untardir):
            os.makedirs(untardir)
        untar_files(fp, untardir)
        _log.info("Files untard to %s", untardir)
        for zfile in [os.path.join(untardir, entry) for entry in os.listdir(untardir) if os.path.splitext(entry)[-1] == ".zip"]:
            unzip_images(zfile, untardir)
            _log.info("Images from zip file %s unzipped to %s", zfile, untardir)
        img_filepaths = [os.path.join(untardir, entry) for entry in os.listdir(untardir) if os.path.splitext(entry)[-1] == ".img"]
        _log.info("Processing image files:\n%s", "\n".join(img_filepaths))
        for imgfp in img_filepaths:
            process_imagefile(imgfp, hashdb, source_id)
        shutil.rmtree(untardir)
        _log.info("Removed temp dir: %s", untardir)
        dbif = plyvel.DB(sourcesdb, create_if_missing=True)
        dbif.put(bytes(md5val, encoding="utf8"), bytes(json.dumps({"processed":str(datetime.datetime.now()), "source_id":source_id, "source":source}), encoding="utf8"))
        dbif.close()
        _log.info("Source processed!: %s", source)


def process_imagefile(fp, hashdb, source):
    _log.info("Processing image file %s...", fp)

    mounted, tempdir = False, False
    if filesystem.is_sparseext4(fp):
        _log.info("Detected sparse image")
        curfp = fp
        fp = os.path.join(os.path.dirname(fp), "unsparsed." + os.path.basename(fp))
        if os.path.exists(fp):
            _log.info("Unsparsed allready found at %s, no need to unsparse.", fp)
        else:
            with open(curfp, "rb") as infd, open(fp, "wb") as outfd:
                simg2img.unsparse(infd, outfd)
    if filesystem.is_yaffs_image(fp):
        _log.info("Detected yaffs image")
        rootpath = filesystem.unpack_yaffs(fp, TMPDIR)
    elif filesystem.is_boot_image(fp):
        _log.info("Detected android boot image")
        ramdisk_blob = bootimg.extract_ramdisk(fp)
        rootpath = bootimg.unpack_ramdisk(ramdisk_blob, TMPDIR)
        with open(os.path.join(rootpath, "vmlinuz"), "wb") as ofh:
            ofh.write(bootimg.extract_kernel(fp))
    elif filesystem.is_bootloader_image(fp):
        _log.info("Detected android bootloader image, not supported yet")
        rootpath = os.path.join(TMPDIR, "bootloader_content")
        if not os.path.isdir(rootpath):
            os.mkdir(rootpath)
    else:
        _log.info("Assuming file system image which is known by mount")
        rootpath = filesystem.mount_image(fp, TMPDIR)
        mounted = True

    build_whitelist.configure(dbpath=hashdb)
    dbcreated = False
    if not os.path.exists(hashdb):
        dbcreated = True
    build_whitelist.configure(dbif=plyvel.DB(hashdb, create_if_missing=True))
    _log.info("Connected to Ldb database %s", repr(hashdb))

    build_whitelist.explore_filesystem(rootpath, sourceid=source,
                                       threat=build_whitelist.THREAT_LEVELS["good"],
                                       trust=build_whitelist.TRUST_LEVELS["high"])
    # In case this script is run as sudo because of mounting, we want to change the owner to actual user
    if os.environ["SUDO_USER"] and dbcreated:
        subprocess.check_call(["chown", "-R", "{}:{}".format(os.environ["SUDO_UID"], os.environ["SUDO_GID"]), hashdb])
        _log.info("Owner of %s set to %s:%s", hashdb,os.environ["SUDO_UID"], os.environ["SUDO_GID"])
    if mounted:
        filesystem.unmount_image(rootpath)
    shutil.rmtree(rootpath)
    _log.info("Temp dir %s deleted", rootpath)
    _log.info("Done with image file: %s", fp)

def main():
    parser = argparse.ArgumentParser(description="Build a hash whitelist from the AOSP images. Downloads and processes the images found on AOSP website.")
    parser.add_argument("hashdb", help="Path to existing or non-existing leveldb database to store hashes")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    sourcesdb = args.hashdb.rstrip(".db") + ".sources.db"
    build(args.hashdb, sourcesdb)
    pass

if __name__ == "__main__":
    main()