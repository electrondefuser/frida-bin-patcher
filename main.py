import argparse
from patchagent import Patcher

class Main:
    parser = argparse.ArgumentParser()
    parser.add_argument('-b','--binarypath', type=str, nargs='?', help='location of frida binary to patch (server or gadget)')
    parser.add_argument('-o','--output', type=str, nargs='?', help='output location for new binary')
    parser.add_argument('-v','--verify', action="store_true", help='enable verification')

    args = parser.parse_args()
    patcher = Patcher()

    if patcher.check_path(args.binarypath):
        patcher.initiate_patching_process(patcher, args.binarypath, args.output)

    if args.verify:
        Patcher.verify_patched_binary(patcher, args.output)