#!/usr/bin/env python3

import os

def read_and_print_file(filename):
    try:
        with open(filename, 'r') as file:
            for line in file:
                print(line.rstrip())
                os.system(line.rstrip())
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    file_path = "/Shared/htb-writeups/Boxes/Challenge Labs/1-Medtech/tmp/scripts/script-data.txt"
    read_and_print_file(file_path)
