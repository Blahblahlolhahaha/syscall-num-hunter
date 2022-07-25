import json
from operator import index
import sys
def main():
    cry :dict= json.load(open("syscalls.json"))
    if(len(sys.argv)) == 1:
        print("Usage:python sad.py <syscall_num>")
        exit(1)
    syscall_num = sys.argv[1]
    if not syscall_num.startswith("0x"):
        syscall_num = "0x" + syscall_num
    if list(cry.keys).count(syscall_num) == 0:
        print("Number does not exist!")
    else:
        print(cry[syscall_num])


if __name__ == "__main__":
    main()
    