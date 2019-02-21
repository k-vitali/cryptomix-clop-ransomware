# @VK_Intel
# Cryptomix sample: SHA-256: 79b8c37a5e2a32e8f7e000822cec6f2f4e317620a2296f1aa3f35b2374c396ec
'''
Usage:
python cryptomix_rsrc_decoder.py --mal unpacked_mal.exe --out out.bin
'''

import pefile
import argparse

#the variable used to store our raw config data
first_blob = "" 
second_blob = "" 
offset = 0x0
size = 0x0
key=bytearray(b'Po39NHfwik237690t34nkjhgbClopfdewquitr362DSRdqpnmbvzjkhgFD231ed76tgfvFAHGVSDqhjwgdyucvsbCdigr1326dvsaghjvehjGJHGHVdbas')
xor_key = 0x42

def get_section_blob(peL, rsrc_name):
    for rsrc in peL.DIRECTORY_ENTRY_RESOURCE.entries:
        if rsrc.name.__str__() == rsrc_name:
            for entry in rsrc.directory.entries:
                offset = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
    return peL.get_memory_mapped_image()[offset:offset+size]


def xor_decode(key, blob):
	encoded = bytearray(blob)
	for i in range(len(encoded)):
		encoded[i] ^= key[i % xor_key]
		encoded.decode('ascii', 'replace')
	return encoded

def dump_to_file(filename, data):
    with open(filename, 'ab') as f:
        f.write(data)    

def main():
    parser = argparse.ArgumentParser(description="Cryptomix Resource Decoder by @VK_Intel \n")
    parser.add_argument('--mal',dest="malware",default=None,help="File with unpacked malware", required=True)
    parser.add_argument('--out',dest="outfile",default="out.bin", help="Where to dump the output", required=False)
    args = parser.parse_args()
    global pe
    pe = pefile.PE(args.malware)
    rsrc = get_section_blob(pe,"OFFNESTOP1")
    rsrc2 = get_section_blob(pe,"OFFNESTOP")
    dec_rsrc1 = xor_decode(key, rsrc)
    dec_rsrc2 = xor_decode(key, rsrc2)
    if dec_rsrc1 and dec_rsrc2 is not None:
        dump_to_file(args.outfile, dec_rsrc1)
        print("\n[*] First decoded resource section: %s" % (dec_rsrc1))
        dump_to_file(args.outfile, dec_rsrc2)
        print("\n[*] Second decoded resource section: %s" % (dec_rsrc2))
        print("Dumped decoded to: %s" % (args.outfile))
        return

    if dec_rsrc1 and dec_rsrc2 is None:
        print("Output is empty")
        return

if __name__ == '__main__':
    main()
