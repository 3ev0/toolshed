import binascii
import logging
import subprocess
import sys

import click

encmap = {"s": "ascii", 
        "S": "utf8",
        "l": "utf_16_le",
        "b": "utf_16_be",
        "L": "utf_32_le",
        "B": "utf_32_be"}
@click.group()
def cli():
    """ Script to patch strings in (binary) file. 
The script works with output format of unix 'strings' utility.
     """

@cli.command()
@click.option("--enc", "-e", default="l", type=click.Choice(["s", "S", "b", "l", "B", "L"]), help="Select character size and endianness: s = 7-bit, S = 8-bit, {b,l} = 16-bit, {B,L} = 32-bit")
@click.argument("filepath", type=click.Path(writable=True))
def show(filepath, enc):
    """ Run strings on the file and output results. Outputs list of <offset> <string> """
    click.echo("# Strings output:")
    click.echo("# encoding parameter: %s"%enc)
    click.echo("# filepath: %s"%filepath)
    click.echo("# =====================")
    results = subprocess.check_output(["strings", "-a", "-t", "d", "-e", enc, filepath])
    sys.stdout.write(str(results, encoding="ascii"))

@cli.command()
@click.option("--enc", "-e", default="l", type=click.Choice(["s", "S", "b", "l", "B", "L"]), help="Select character size and endianness: s = 7-bit, S = 8-bit, {b,l} = 16-bit, {B,L} = 32-bit")
@click.argument("filepath", type=click.Path(writable=True))
def patch(filepath, enc):
    p_enc = encmap[enc]
    """ Patch the strings in file. 
Reads list of '<offset> <string>' entry from stdin """
    with open(filepath, "r+b") as f:
        entries = sys.stdin.read().splitlines(False)
        click.echo("%d entries"%len(entries))
        for entry in entries:
            if not entry or entry.startswith("#"):
                continue
            (offset, rplstr) = entry.lstrip().split(" ", maxsplit=1)
            
            ioffset = int(offset.strip())
            f.seek(ioffset,0)
                    
            bytestr = bytes(rplstr, p_enc)
            targetbytes = f.read(len(bytestr))
            if bytestr != targetbytes:
                click.echo("Patched at %d: %s -> %s"%(ioffset, targetbytes, bytestr))
            f.seek(int(offset.strip()),0)
            f.write(bytestr)
    
#    results = subprocess.check_output(["strings", "-a", "-t", "d", "-e", enc, filepath])
#    click.echo("# New strings output")
#    click.echo("# ==================")
#    sys.stdout.write(str(results, encoding="ascii"))



    
if __name__ == "__main__":
    cli()
