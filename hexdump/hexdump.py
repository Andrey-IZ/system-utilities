#!/usr/bin/env python

from __future__ import print_function
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import os
import sys
import struct
import binascii
import time
import platform
import datetime
import re

IS_OUTPUT = False


def print_dump(outfile, block_size, addr_start, output_type, list_bytes, list_prev, pattern=None):
    list_addr_str = []
    list_text = []

    e = block_size // 2
    offset = addr_start

    if not list_prev:
        list_prev = list_bytes

    for chunk in list_bytes:
        list_addr_str.append(str("{0}:".format(hex(offset)[2:].zfill(8))))

        list_text.append(handle_text(chunk))
        offset += len(chunk)

    for i, line in enumerate(list_addr_str):
        if IS_OUTPUT:
            output_left, size_left = show_output(block_size, list_bytes[i][:e], output_type, list_prev[i][:e], pattern=pattern)
            output_right, size_right = show_output(block_size, list_bytes[i][e:], output_type, list_prev[i][:e], pattern=pattern)
            s = '{0}  {1:'+ str(size_left)+ 's}  {2:' + str(size_right) + 's} |{3:'+str(block_size)+'s}|'
            outfile.write(s.format(line, output_left, output_right, list_text[i]) + os.linesep)

        output_left, size_left = show_output(block_size, list_bytes[i][:e], output_type, list_prev[i][:e],
                                                        nullColor=Colors.fg.red,
                                                        prevColor=Colors.reverse, pattern=pattern)
        output_right, size_right = show_output(block_size, list_bytes[i][e:], output_type, list_prev[i][e:],
                                                        nullColor=Colors.fg.red,
                                                        prevColor=Colors.reverse, pattern=pattern)

        s = '{0}  {1:'+ str(size_left)+ 's}  {2:' + str(size_right) + 's} |{3:'+str(block_size)+'s}|'
        print(s.format(Colors.bold + line + Colors.reset, output_left, output_right, list_text[i]))


def make_dump(file, block_size, output_type, sleep=0, from_addr=0, length=0x10, pattern=None):
    list_prev = []
    path = os.path.abspath(os.path.curdir) + '/' + os.path.basename(file) + ".dump"
    with open(path, 'w') as outfile:
        screen_clear()
        while True:
            if IS_OUTPUT:
                cprint(outfile, '{0}, len={1}, path={2}'.format(datetime.datetime.now(), length, path))
            else:
                cprint(outfile, '{0}, len={1}'.format(datetime.datetime.now(), length))
            offset = from_addr
            list_cur_mem = []
            with open(file, 'rb') as infile:
                infile.seek(offset)
                while True:
                    chunk = infile.read(block_size)
                    if len(chunk) == 0:
                        break

                    list_cur_mem.append(chunk)

                    offset += block_size
                    if length != 0 and (offset - from_addr) > length:
                        break

            print_dump(outfile, block_size, from_addr, output_type, list_cur_mem, list_prev, pattern=pattern)
            list_prev = list_cur_mem

            if sleep <= 0:
                break
            time.sleep(sleep)
            screen_clear()


def cprint(output_file, text, end=os.linesep):
    if IS_OUTPUT:
        output_file.write(text + end)
    print(text, end=end)


def screen_clear():
    if re.match('linux', platform.system(), re.IGNORECASE):
        os.system('clear')
    elif re.match('win', platform.system(), re.IGNORECASE):
        os.system('cls')


def show_output(block_size, chunk, output_type, prevChunk, nullColor=None, prevColor=None, pattern=None):
    output_row = ''
    output = ''
    fill_width = 1
    # if output_type == 'u8':
    fill_width = block_size + block_size//(int(output_type[1:])//4)
    # elif output_type == 'u32':
        # fill_width = block_size + block_size//8
    if len(chunk) == 0:
        return '', fill_width

    def repl_func_null(m):
        key = m.group(1)
        return "{1}{0}{2}".format(key, nullColor, Colors.reset) 

    def repl_func_prev(m):
        key = m.group(1)
        return "{1}{0}{2}".format(key, prevColor, Colors.reset)

    if pattern:
        re_f = re.compile('(' + pattern +')')    
    else:
        re_f = re.compile('([0]{' + str(int(output_type[1:])//4) + '})')
    
    if output_type == 'u8' and chunk:       
        output = " ".join("{0:02X}".format(ord(c)) for c in struct.unpack('c' * len(chunk), chunk))

        if nullColor:
            list_row = []
            for i, row in enumerate(output.split(' ')):
                list_row.append(re.sub(pattern=r'((?!' + "{0:02X}".format(bytearray(prevChunk)[i]) + r').{2})',
                                       repl=repl_func_prev, string=row))

            output_row = ' '.join(list_row)
            output_row = re_f.sub(repl=repl_func_null, string=output_row)

    elif output_type == 'u32' and chunk:
        if len(chunk) % 4 == 0:
            output = " ".join(
                "{0:08X}".format(i) for i in struct.unpack('I' * (len(chunk) // 4), chunk))
            if nullColor:
                list_row = []
                unpacked_bytes = struct.unpack('I' * (len(prevChunk) // 4), prevChunk)
                for i, row in enumerate(output.split(' ')):
                    list_row.append(re.sub(pattern=r'((?!' + "{0:08X}".format(unpacked_bytes[i]) + r').{8,})',
                                           repl=repl_func_prev, string=row))

                output_row = ' '.join(list_row)
                output_row = re_f.sub(repl=repl_func_null, string=output_row)
    fill_width += len(output_row) - len(output)

    return output_row, fill_width


def is_python2():
    return sys.version[0] == '2'


def handle_text(chunk):
    if is_python2():
        text = ''.join(['*' if ord(i) > 0 else '.' for i in bytes(chunk)])
    else:
        text = ''.join(['*' if ord(chr(i)) > 0 else '.' for i in bytes(chunk)])
    
    return text


class Colors:
    reset = '\033[0m'
    bold = '\033[01m'
    disable = '\033[02m'
    underline = '\033[04m'
    reverse = '\033[07m'
    strikethrough = '\033[09m'
    invisible = '\033[08m'

    class fg:
        black = '\033[30m'
        red = '\033[31m'
        green = '\033[32m'
        orange = '\033[33m'
        blue = '\033[34m'
        purple = '\033[35m'
        cyan = '\033[36m'
        lightgrey = '\033[37m'
        darkgrey = '\033[90m'
        lightred = '\033[91m'
        lightgreen = '\033[92m'
        yellow = '\033[93m'
        lightblue = '\033[94m'
        pink = '\033[95m'
        lightcyan = '\033[96m'

    class bg:
        black = '\033[40m'
        red = '\033[41m'
        green = '\033[42m'
        orange = '\033[43m'
        blue = '\033[44m'
        purple = '\033[45m'
        cyan = '\033[46m'
        lightgrey = '\033[47m'


def main():
    app_name = os.path.basename(sys.argv[0])
    usage = app_name + ''' [-h] [-w {8,16,32}] [-o] [--from FROM_ADDR]
                  [--length LENGTH] [--type {u8,u32}] [--update UPDATE]
                  file
    ''' + '''
    Examples: 
        {0} /dev/file
        {0} /dev/file --pattern=00\\w+ 
        {0} /dev/file --pattern=00\\w+ -o
        {0} /dev/file --length=100 --type=u32 -w=16 --update=0.1
        {0} /dev/file --length=100 --from=200 --type=u32 -w=32 --update 0.5 -o
        {0} /dev/file --length=400 --from=10 --type=u8 -w=8 --update=0.1 --output
    '''.format(app_name)
    
    description = 'Shows the hex view of the file (device)'
    epilog = '''(c) Andrew 2019. Copyright and Related Rights Regulations (2019 No. 3)'''
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter, usage=usage, description=description, epilog=epilog)
    parser.add_argument("file", help="Specify the file")
    parser.add_argument("-w", "--width", help="Show width size", choices=[8, 16, 32], type=int, default=16)
    parser.add_argument("-o", "--output", dest='save_to_file', help="Save log output to file (*.dump)", action="store_true")
    parser.add_argument("--from", dest='from_addr', type=int, help="address from whom should make dump",
                        default=0)
    parser.add_argument("--length", type=int, help="length of block whom should make dump", default=0)
    parser.add_argument("--type", choices=['u8', 'u32'], help="set type of output", default='u8')
    parser.add_argument("--update", type=float, help="set loopable timer", default=0)
    parser.add_argument("--pattern", help="set pattern for selecting", default='')
    args = parser.parse_args()

    global IS_OUTPUT
    IS_OUTPUT = args.save_to_file
    if args.file:
        make_dump(args.file, args.width, args.type, sleep=args.update, from_addr=int(str(args.from_addr),16), 
                 length=int(str(args.length), 16), pattern=args.pattern)
    else:
        print(parser.usage)


if __name__ == '__main__':
    main()
