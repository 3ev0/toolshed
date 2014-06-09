#/usr/bin/env python
import logging
import argparse
import os
import os.path
import subprocess
import hashlib
import json
import shutil
import stat

import plyvel

from android import filesystem
from android import simg2img

TRUST_LEVELS = {"high":2, # Known good source
                "medium":1, # Source probably good, but not verified
                "low":0} # Source trust unknown

THREAT_LEVELS = {"good":0,
                 "evil":1}

_log = logging.getLogger()
_tempdir = "/tmp"
_config = {"tempdir":"/tmp",
          "dbpath": "hashes.db",
          "dbif": None
          }

def configure(**kwargs):
    _config.update(**kwargs)

def _update_value(curval, value):
   newval = {"filepath":value["filepath"],
             "source_id":value["source_id"],
             "threat":value["threat"],
             "trust":value["trust"]
            }

   return newval

def batch_write(items, replace=True):
    _log.debug("Batch write of %d items to %s", len(items), repr(_config["dbif"]))
    num_added, num_procd, dupl = 0, 0, 0
    with _config["dbif"].write_batch() as wb:
        for hashes,value in items:
            for hash in hashes:
                num_procd += 1
                curval = _config["dbif"].get(hash)
                if curval:
                    _log.info("%s allready present in db", repr(hash))
                    dupl += 1
                    if not replace:
                        _log.info("not added")
                        continue
                    else:
                        newval = _update_value(json.loads(str(curval, encoding="utf8")), value)
                        wb.put(hash, bytes(json.dumps(newval), encoding="utf8"))
                        num_added += 1
                        _log.info("Replaced with %s", newval)
                else:
                    wb.put(hash, bytes(json.dumps(value), encoding="utf8"))
                    _log.debug("%s added to database", repr(hash))
    return num_added, num_procd, dupl

def hash_file(filepath):
    _log.debug("Hashing %s", filepath)
    with open(filepath, mode="br") as fh:
        mmd5 = hashlib.md5()
        msha1 = hashlib.sha1()
        msha256 = hashlib.sha256()
        blob = fh.read(1024*1024)
        while blob:
            mmd5.update(blob)
            msha1.update(blob)
            msha256.update(blob)
            blob = fh.read(1024*1024)
    return mmd5.digest(), msha1.digest(), msha256.digest()



def explore_filesystem(rootpath, sourceid=None, threat=None, trust=None):
    dbif = _config["dbif"]
    _log.info("Exploring from root %s...", rootpath)

    batch_size = 1024
    batch = []
    total_added, total_procd, total_dupl = 0, 0, 0
    for (root, dirs, files) in os.walk(rootpath, followlinks=False):
        for fl in files:
            fp = os.path.join(root, fl)
            _log.info("Encountered file %s", fp)
            if stat.S_ISLNK(os.lstat(fp).st_mode):
                _log.info("Is symlink, so skipped")
                continue
            hashes = hash_file(fp)
            batch.append((hashes, {"source_id": sourceid,
                                   "threat":threat,
                                   "trust":trust,
                                   "filepath":fp}))
            if len(batch) >= batch_size:
                added, procd, dupl = batch_write(batch)
                total_added, total_procd, total_dupl = total_added + added, total_procd + procd, total_dupl + dupl
                batch = []
    added, procd, dupl = batch_write(batch)
    total_added, total_procd, total_dupl = total_added + added, total_procd + procd, total_dupl + dupl
    _log.info("Done exploring!")
    _log.info("%d records processed", total_procd)
    _log.info("%d records allready in db", total_dupl)
    dbif.close()

def main():
    parser = argparse.ArgumentParser(description="Build hash list from images files or dirs")
    parser.add_argument("source", help="Image file or dir")
    parser.add_argument("-i", "--id", default="unknown", help="Provide source identifier to be stored with the hashes")
    parser.add_argument("-t", "--threat", default="good", choices=list(THREAT_LEVELS.keys()), help="The threat level of these files")
    parser.add_argument("-r", "--trust", default="high", choices=list(TRUST_LEVELS.keys()), help="The trust level of these files")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debugging")
    parser.add_argument("-o", "--output", default="hashes.db", help="The output database. If existing, the data is added. Default: hashes.db")
    parser.add_argument("-f", "--format", choices=["ldb", "sql"], default="ldb", help="The output format. Default: ldb")
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    global _log

    _config["dbpath"] = args.output
    dbcreated = False
    if args.format == "ldb":
        if not os.path.exists(_config["dbpath"]):
            dbcreated = True
        _config["dbif"] = plyvel.DB(_config["dbpath"], create_if_missing=True)
        _log.info("Connected to Ldb database %s", repr(_config["dbif"]))
    else:
        raise Exception("db format not implemented")

    source = os.path.abspath(args.source)
    _log.info("New source: %s...", source)
    tempdir, mounted = False, False
    if not os.path.exists(source):
        _log.error("Path does not exist")
    if os.path.isfile(source):
        if filesystem.is_sparseext4(source):
            _log.info("Smells like sparse ext4 image")
            curfp = source
            source = os.path.join(os.path.dirname(source), "unsparsed." + os.path.basename(source))
            with open(curfp, "rb") as infd, open(source, "wb") as outfd:
                simg2img.unsparse(infd, outfd)
        if filesystem.is_yaffs_image(source):
            _log.info("Smells like yaffs image")
            rootpath = filesystem.unpack_yaffs(source)
        else:
            _log.info("Doesn't smell familier, i'll try to mount")
            rootpath = filesystem.mount_image(source)
            mounted = True
        tempdir = True
    else:
        _log.info("assuming this the root of file tree")
        rootpath = source

    explore_filesystem(rootpath, sourceid=args.id, threat=args.threat, trust=args.trust)
    # In case this script is run as sudo because of mounting, we want to change the owner to actual user
    if os.environ["SUDO_USER"] and dbcreated:
        subprocess.check_call(["chown", "-R", "{}:{}".format(os.environ["SUDO_UID"], os.environ["SUDO_GID"]), _config["dbpath"]])
        _log.info("Owner of %s set to %s:%s", _config["dbpath"],os.environ["SUDO_UID"], os.environ["SUDO_GID"])
    if mounted:
        mounting.unmount_image(rootpath)
    if tempdir:
        shutil.rmtree(rootpath)
        _log.info("Temp dir %s deleted", rootpath)

if __name__ == "__main__":
    main()
