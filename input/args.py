import os
import subprocess

args = "\x41 "*64 + "\x00 " + "\x42 "*33 + "\x43"
p = subprocess.Popen(["./input", args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE);
print p.stdout.readline()
print p.stdout.readline()
print p.stdout.readline()
print p.stdout.readline()
