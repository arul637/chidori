from typing import List, Tuple
import time
from enum import Enum
from numpy import linspace
import threading 
import argparse
import hashlib 
import sys

banner = """
           ░██        ░██        ░██                     ░██
           ░██                   ░██                     
 ░███████  ░████████  ░██  ░████████  ░███████  ░██░████ ░██
░██    ░██ ░██    ░██ ░██ ░██    ░██ ░██    ░██ ░███     ░██
░██  K     ░██  I ░██ ░██ ░██  R ░██ ░██  A ░██ ░██      ░██
░██    ░██ ░██    ░██ ░██ ░██    ░██ ░██    ░██ ░██      ░██
 ░███████  ░██    ░██ ░██  ░█████░██  ░███████  ░██      ░██

                Multithreaded Password Cracker

                Version  :  v1.0.0
                Author   :  Arulkumaran S
                Year     :  2025
"""

start_time = time.time() 

class HashMethod(Enum):
    # MD5
    MD5 = "md5"

    # SHA Family
    SHA1 = "sha-1"
    SHA224 = "sha-224"
    SHA256 = "sha-256"
    SHA384 = "sha-384"
    SHA512 = "sha-512"

    # SHA3 Family
    SHA3_224 = "sha3-224"
    SHA3_256 = "sha3-256"
    SHA3_384 = "sha3-384"
    SHA3_512 = "sha3-512"

    # BLAKE2 Family
    BLAKE2B = "blake-2b"
    BLAKE2S = "blake-2s"

    # SHAKE Family
    SHAKE_128 = "shake-128"
    SHAKE_256 = "shake-256"

class PasswordCracker:
    def __init__(self, algorithm: HashMethod, wordlist_path: str, thread_count: int, hash_file: str = None, hash: str = None):
        self.hash = hash
        self.hash_file = hash_file
        self.algorithm = algorithm
        self.wordlist = []
        self.wordlist_path = wordlist_path
        self.thread_count = thread_count
        self.found = False
        self.lock = threading.Lock() 
    
    def hash_converter(self, input_string: str) -> "hashlib._Hash":
        if self.algorithm == HashMethod.MD5.value:
            return hashlib.md5(input_string.encode())
        elif self.algorithm == HashMethod.SHA1.value:
            return hashlib.sha1(input_string.encode())
        elif self.algorithm == HashMethod.SHA224.value:
            return hashlib.sha224(input_string.encode())
        elif self.algorithm == HashMethod.SHA256.value:
            return hashlib.sha256(input_string.encode())
        elif self.algorithm == HashMethod.SHA384.value:
            return hashlib.sha384(input_string.encode())
        elif self.algorithm == HashMethod.SHA512.value:
            return hashlib.sha512(input_string.encode())
        elif self.algorithm == HashMethod.SHA3_224.value:
            return hashlib.sha3_224(input_string.encode())
        elif self.algorithm == HashMethod.SHA3_256.value:
            return hashlib.sha3_256(input_string.encode())
        elif self.algorithm == HashMethod.SHA3_384.value:
            return hashlib.sha3_384(input_string.encode())
        elif self.algorithm == HashMethod.SHA3_512.value:
            return hashlib.sha3_512(input_string.encode())
        elif self.algorithm == HashMethod.BLAKE2B.value:
            return hashlib.blake2b(input_string.encode())
        elif self.algorithm == HashMethod.BLAKE2S.value:
            return hashlib.blake2s(input_string.encode())
        elif self.algorithm == HashMethod.SHAKE_128.value:
            return hashlib.shake_128(input_string.encode())
        elif self.algorithm == HashMethod.SHAKE_256.value:
            return hashlib.shake_256(input_string.encode())
        else:
            raise ValueError("Unsupported hash algorithm")

    def brute_forcer(self, start: int, end: int):
        for i in range(start, end):
            if self.found:
                return 
            
            password = self.wordlist[i].strip()
            hash_value = self.hash_converter(password).hexdigest() 
            
            # sys.stdout.flush()
            # sys.stdout.write(f"\r[-] time taken: [{time.time() - start_time: .2f}] {self.hash} -> {password}")
            
            if hash_value == self.hash:
                with self.lock:
                    if not self.found:
                        end_time = time.time()
                        sys.stdout.flush()
                        sys.stdout.write(f"[+] total time taken: [{end_time - start_time: .2f}]")
                        self.found = True
                        sys.stdout.write(f"\n[+] Password found: {password}")
                return

    def wordlist_file_handler(self) -> List[Tuple[int, int]]:
        with open(self.wordlist_path, "r", encoding="latin-1") as wordlist_file:
            self.wordlist = wordlist_file.readlines()
        
        splitter = linspace(0, len(self.wordlist), num=self.thread_count, dtype=int)
        chunks = []

        for i in range(len(splitter) - 1):
            start = splitter[i]
            end = splitter[i+1]
            chunks.append((start, end))

        return chunks



    def crack(self):
        if self.hash_file is not None:
            with open(self.hash_file, 'r') as file:
                self.hash = file.read().strip() 

        chunks = self.wordlist_file_handler() 

        for start, end in chunks:
            thread = threading.Thread(target=self.brute_forcer, args=(start, end))
            thread.start()

if __name__ == "__main__":

    print(banner)
    
    parser = argparse.ArgumentParser(description="Multithreaded Password Cracker")
    parser.add_argument("--hash", type=str,help="The hash of the password to crack")
    parser.add_argument("--hash-file", type=str,help="Path to the file containing hashes to crack")
    parser.add_argument("--algorithm", type=str, help="Hash Algorithm to crack", required=True)
    parser.add_argument("--wordlist", type=str,help="Path to the wordlist file", required=True)
    parser.add_argument("--threads", type=int, default=25, help="Number of threads to use")
    args = parser.parse_args()

    cracker = PasswordCracker(
        algorithm=args.algorithm,
        wordlist_path=args.wordlist,
        thread_count=args.threads,
        hash_file=args.hash_file,
        hash=args.hash)
    
    cracker.crack()