# Introduction
Tool to split the header and body of an OpenPGP digital envelope

# Why you need it
OpenPGP is great, but there are a lot of meta-data included in its digital envelope. If you use that to encrypt a huge file, then upload the result onto a file-sharing service, in order to share the file to your friend, the provider of the service you choose may be able to track you and the recipient.

OpenPGP digital envelopes consist of a small, structural and meta-data-rich header, and a much larger, symmetrically-encrypted, structure-lacking body, so you can split its header and body, transfer the header via more secure channel (e.g. OTR), and only share the body via file-sharing services. Thus, the service provider can only notice that you have uploaded a seemingly structureless blocks of random bytes, and another person downloaded it.

# Technical details
`python-pgpdump` is used to parse OpenPGP data structures, and mmap-based zero copy is used to operate large files.

The first two bytes of the "real" body part is devided into the header, and the offset is rounded to a multiple of 3, in order to make base64 more effective.

Con-cat(1)-enating the binary header file and the body file gives us the original OpenPGP input, and de-base64(1)-ing the `header` field of the json-formatted header file gives us the binary header file.

You could get the point how to assemble the original OpenPGP input from its split header and body with no `mamiru` executable at hand.

# To make the life of those who run surveillance harder.
gnupg tends to produce partialized symmetrically-encrypted body if compression before encryption is enabled. Bodies in such format contain equidistantly distributed part-length info, which may become a clue, so it is suggested to use other tools (e.g. gzip, xz, zip, 7z) to perform compression, and encrypt the compressed data (including epub and compact image and video files) by gnupg with compression disabled (`-z 0`), when used along with `mamiru`.
