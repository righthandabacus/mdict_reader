# mdict_reader
Extract data from Octopus mdict (*.mdd, *.mdx) files

```
usage: tool.py [-h] [-l] [-a] [-x EXTRACT] [-d DIR] [-o OUTPUT] [-e TRANSCODE]
               mdict_file

mdict tool

positional arguments:
  mdict_file            Input *.mdx or *.mdd file

optional arguments:
  -h, --help            show this help message and exit
  -l, --list            List entry names in MDX or file names in MDD
  -a, --dump            Dump all files in *.mdd into files in output dir or
                        all entries in *.mdx into a CSV
  -x EXTRACT, --extract EXTRACT
                        Extract one file or entry content, print to stdout if
                        -o not specified. Argument should be specified in
                        UTF-8
  -d DIR, --dir DIR     Output directory for -a or -o
  -o OUTPUT, --output OUTPUT
                        Output filename for -x
  -e TRANSCODE, --transcode TRANSCODE
                        Transcode data, specified in format of
                        INPUT_ENC:OUTPUT_ENC
```
