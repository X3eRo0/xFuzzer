import concurrent.futures
import random
import struct
import signal
import curses
import sys
import os

from subprocess import DEVNULL, PIPE, Popen
from optparse import OptionParser
from datetime import datetime

# standard curses screen
stdscr = None


def build_parser():
    usage = 'usage: %prog [options]'
    parser = OptionParser(usage)
    parser.add_option('-i', '--input',                                    dest = 'input',    help = 'target executable')
    parser.add_option('-c', '--crash',         default = 'crash/',        dest = 'crash',    help = 'crash sample directory')
    parser.add_option('-m', '--mutated',       default = 'mutated/',      dest = 'mutated',  help = 'mutated sample directory')
    parser.add_option('-t', '--testfile',      default = 'input.sample',  dest = 'testfile', help = 'test file')
    parser.add_option('-s', '--save',             default = False,           dest = 'save_m',   help = 'save mutated file', action="store_true")
    parser.add_option('-w', '--workers',             default = 4,           dest = 'workers',   help = 'no of workers',)
    return parser

def signal_handler(sig, frame):
    os._exit(-1)

def log_save(data):
    with open("log.txt", "a") as f:
        f.write("[*] "+ datetime.now().strftime("%m/%d/%Y, %H:%M:%S") + " " + data + "\n")

def load_file(fname):
    try:
        with open(fname, "rb") as f:
            return bytearray(f.read())
    except:
        print("[-] Cannot Open testcase")
        sys.exit(-1)

def save_file(fname, data):
    with open(fname, "wb") as f:
        f.write(data)

def bit(data):
    count = int((len(data) * 8) * 0.01)
    if count == 0:
        count = 1
    for _ in range(count):
        bit = random.randint(0, len(data) * 8 - 1)
        idx_bit = bit % 8
        idx_byte = int(bit / 8)
        data[idx_byte] |= 1 << idx_bit
        data[idx_byte] &= 1

    return data

def byte(data):
    count = int(len(data) * 0.01)
    if count == 0:
        count = 1
    for _ in range(count):
        data[random.randint(0, len(data) - 1)] = random.randint(0, 255)
    return data

def radamsa(fname):

    proc = Popen(["radamsa", fname],
                 stdout=PIPE,
                 stderr=DEVNULL,
                 stdin =DEVNULL
                 )
    stdout = proc.communicate()
    return stdout[0]

def magic(data):

    numbers = [
        (1, struct.pack("B", 0xff)),
        (1, struct.pack("B", 0x7f)),
        (1, struct.pack("B", 0)),
        (2, struct.pack("H", 0xffff)),
        (2, struct.pack("H", 0)),
        (4, struct.pack("I", 0xffffffff)),
        (4, struct.pack("I", 0)),
        (4, struct.pack("I", 0x80000000)),
        (4, struct.pack("I", 0x40000000)),
        (4, struct.pack("I", 0x7fffffff)),
    ]

    count = int(len(data) * 0.01)

    if count == 0:
        count = 1

    for _ in range(count):
        n_size, n = random.choice(numbers)
        sz = len(data) - n_size
        if sz < 0:
            continue

    idx = random.randint(0, sz)
    data[idx:idx + n_size] = bytearray(n)

    return data

def mutate(data):

    return random.choice([
        #bit,
        #byte,
        #magic,
        radamsa
    ])(data[::])


def run(exename, mutatedf, mutated_sample, counter):
    
    try:
        pro = Popen(
            [exename, mutatedf],
            stdout=DEVNULL,
            stderr=DEVNULL,
            stdin =DEVNULL
            )

        out, _ = pro.communicate(None, 4)
        sta = pro.returncode
    except:
        sta = -1
        
    return sta, mutated_sample, counter

no_normals = 0
no_crashes = 0
no_timeout = 0
workers    = 4
exename    = ""
executor   = None

parser          = build_parser()
(options, args) = parser.parse_args()

def main():

    #input_sample = [load_file(options.testfile), options.testfile]
    path = os.path.abspath(__file__)

    if not os.path.exists(options.crash):
        os.mkdir(options.crash)
    if not os.path.exists(options.mutated):
        os.mkdir(options.mutated)

    global exename
    global workers
    global stdscr
    global exename

    exename = options.input
    if options.workers:
        workers = int(options.workers)

    counter = 0
    stdscr = curses.initscr(); curses.noecho()

    with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
        while True:
            counter += 1 
            mutated_sample = mutate(options.testfile)
            mutatedf = options.mutated + "mutatedf.%.5i" % counter
            
            if options.save_m:
                save_file(mutatedf, mutated_sample)
            else:
                mutatedf = options.mutated + "last_mutated"
                save_file(mutatedf, mutated_sample)
            
            f = executor.submit(
                run,
                exename=exename,
                mutatedf=mutatedf,
                mutated_sample=mutated_sample,
                counter=counter
            )

            f.add_done_callback(do_with_output)


def do_with_output(future):

    global no_normals
    global no_crashes
    global no_timeout
    global stdscr

    output, mutated_sample, i = future.result()

    try:
        # -11 for segfault
        if output == -11:

            save_file(options.crash + "crash.samples.%.5i" % i, mutated_sample)
            type_ = "[%3i] sample-%.5i CRASHED!" % (output, i)
            no_crashes += 1

        # -1 for timeout
        elif output == -1:
        
            type_ = "[%3i] sample-%.5i TIMEOUT!" % (output, i)
            no_timeout += 1
        
        # all other code for NORMAL exits
        else:
            type_ = "[%3i] sample-%.5i NORMAL !" % (output, i)
            no_normals += 1

        log_save(type_)
        stdscr.addstr(0, 0, "-=[ X3eRo0's Fuzzer is fuzzing " + exename + " ]=-", curses.A_BLINK)
        stdscr.addstr(1, 3, "[+] No of Normal Exits : " + hex(no_normals), curses.A_BOLD)
        stdscr.addstr(2, 3, "[+] No of Crashes      : " + hex(no_crashes), curses.A_BOLD)
        stdscr.addstr(3, 3, "[+] No of Timeout      : " + hex(no_timeout), curses.A_BOLD)
        stdscr.addstr(4, 3, "[*] " + type_                               , curses.A_BOLD)
        stdscr.refresh()
        '''
        sys.stdout.write("[+] No of Normal Exits: " + hex(no_normals) + "\n")
        sys.stdout.write("[+] No of Crashes     : " + hex(no_crashes) + "\n")
        sys.stdout.write("[+] No of Timeout     : " + hex(no_timeout) + "\n")
        sys.stdout.write("[*] " + type_ +"\033[F\033[F\033[F")
        sys.stdout.flush()
        '''
    except Exception as e:
        
        print(e)



if __name__ == "__main__":
    
    signal.signal(signal.SIGINT, signal_handler)
    main()
    curses.endwin()
    #radamsa("./hw")
