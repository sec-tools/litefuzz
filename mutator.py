#!/usr/bin/python3
# -*- coding: UTF-8 -*-
#
# litefuzz project
#
# mutator.py
#
#

import os
import sys
import random

import misc
import config
import settings

if(str(sys.platform).startswith('linux')):
    try:
        import pyradamsa
    except:
        settings.RADAMSA_MUTATOR_ENABLE = False

#
# simple mutator that flips random bytes at a random indicies
#
def flip(data, mutations):
    if(config.debug):
        print("\n[MUTATOR] flip\n")
        print("mutations: %d\n" % mutations)

    #
    # flip a different index for each mutation
    #
    for x in range(mutations):
        i = misc.getRandomInt(0, (len(data) - 1))
        data[i] = misc.getRandomInt(0, 255)

    return data

#
# flip 1-4 random bytes at a random index with common "magic" high and low values
#
def highLow(data):
    if(config.debug):
        print("\n[MUTATOR] highLow\n")

    #
    # 00, 01, 02, 03, 7E, 7F, 80, 81, FC, FD, FE, FF
    #
    magic = (0, 1, 2, 3, 126, 127, 128, 129, 252, 253, 254, 255)

    size = misc.getRandomInt(1, 4) # random small size

    if(len(data) == 1):
        i = 0
    else:
        i = misc.getRandomInt(0, (len(data) - 1)) # random index

    x = misc.getWithin(i, len(data), size) # random size
    b = random.choice(magic) # random magic

    c = 0

    if(config.debug):
        print("x=%d, i=%d, b=%d\n" % (x, i, b))

    while(c < x):
        data[i + c] = b
        c += 1

    return data

#
# Insert a random number of random bytes at a random location
#
def insert(data):
    if(len(data) == 1):
        i = 0
    else:
        i = misc.getRandomInt(0, (len(data) - 1)) # random index

    size = misc.getRandomInt(settings.SIZE_MIN, settings.SIZE_MAX) # random insert size

    if(config.debug):
        print("\n[MUTATOR] insert\n")
        print("len(data): %d" % len(data))
        print("size:      %d\n" % size)

    #
    # original data len + size
    #
    mutant = bytearray(len(data) + size)

    if(config.debug):
        print("mutant=%d\n" % len(mutant))
        print("size=%d @ i=%d\n" % (size, i))

    c = 0

    #
    # copy data up until index
    #
    try:
        while(c < i):
            mutant[c] = data[c]
            c += 1
    except Exception as error:
        print("\n[ERROR] misc.insertMutator() @ initial copy: %s\n" % error)
        return None

    c = 0

    #
    # two methods here: pick a random byte or make them all random bytes
    #
    b = misc.getRandomInt(0, 255)
    method = misc.getRandomInt(1, 2)

    if(config.debug):
        print("b=%d, method=%d\n" % (b, method))

    #
    # insert mutation
    #
    if(method == 1):
        try:
            while(c < size):
                mutant[i + c] = b
                c += 1
        except Exception as error:
            print("\n[ERROR] misc.insertMutator() @ method=%d: %s\n" % (method, error))
            return None
    if(method == 2):
        try:
            while(c < size):
                mutant[i + c] = misc.getRandomInt(0, 255)
                c += 1
        except Exception as error:
            print("\n[ERROR] misc.insertMutator() @ method=%d: %s\n" % (method, error))
            return None

    #
    # copy starting at mutant index + size the rest of data index
    #

    if(config.debug):
        print("mutant[%d] = data[%d]\n" % ((i + size + c), (i + c)))

    try:
        while (i  < len(data)):
            mutant[i + size] = data[i]
            i += 1
    except Exception as error:
        print("\n[ERROR] misc.insertMutator() @ final copy: %s\n" % error)
        return None

    return mutant # not data

#
# remove random number of bytes at a random index
#
def remove(data):
    if(config.debug):
        print("\n[MUTATOR] remove\n")
        print("len(data): %d" % len(data))

    size = misc.getRandomSize(settings.SIZE_MIN, data)

    if(len(data) == 1):
        i = 0
    else:
        i = misc.getRandomInt(0, (len(data) - 1)) # random index

    x = misc.getWithin(i, len(data), size) # random size

    mutant = data

    if(config.debug):
        print("i=%d @ x=%d\n" % (i, x))

    c = 0

    #
    # keep removing bytes at index until X is hit
    #
    while(c < x):
        mutant.pop(i + c)

        c += 1
        x -= 1

    return mutant

#
# Carve (or slice) out a chunk of bytes at a random location
#
def carve(data):
    if(config.debug):
        print("\n[MUTATOR] carve\n")
        print("len(data): %d" % len(data))

    i = 0
    o = 0

    if(len(data) == 1):
        i = 0
        o = 0
    else:
        while((i == 0) and (o == 0)):
            i = misc.getRandomInt(0, (len(data) - 1)) # random index
            o = misc.getRandomInt(0, (len(data) - 1)) # another random index

    #
    # original data len + x
    #
    mutant = bytearray(len(data))

    if(config.debug):
        print("mutant=%d\n" % len(mutant))
        print("i=%d, o=%d\n" % (i, o))

    #
    # get random slice (carving?)
    #
    if(i < o):
        mutant = data[i:o]
    elif(o < i):
        mutant = data[o:i]
    else:
        mutant = data[:o] # we like to have fun here

    return mutant # not data

#
# Overwrite a random number of random bytes at a random location (without overrun of input size)
#
# note: this mutator is slower than the others (more noticable on fast targets with big inputs)
#
# data = mutant data
# size = random(len(data)) -> random number of bytes, finalizes into x (with consideration of index)
#
def overwrite(data):
    size = misc.getRandomSize(settings.SIZE_MIN, data)

    if(config.debug):
        print("\n[MUTATOR] overwrite\n")
        print("len(data): %d" % len(data))
        print("size:      %d\n" % size)

    if(len(data) == 1):
        i = 0
        x = 1
    else:
        i = misc.getRandomInt(0, size) # random index

        #
        # ensure we can a size that will fit (considering the index)
        #
        x = misc.getWithin(i, len(data), size) # random size

    c = 0

    #
    # two methods here: pick a random byte or make them all random bytes
    #
    b = misc.getRandomInt(0, 255)

    method = misc.getRandomInt(1, 2)

    if(config.debug):
        print("x=%d @ i=%d, b=%s, method=%d\n" % (x, i, b, method))

    if(method == 1):
        try:
            while(c < x):
                data[i + c] = b
                c += 1
        except Exception as error:
            print("\n[ERROR]: %s\n" % error)
    else:
        try:
            while(c < x):
                data[i + c] = misc.getRandomInt(0, 255)
                c += 1
        except Exception as error:
            print("\n[ERROR]: %s\n" % error)

    return data

#
# Use radamsa's mutation engine
#
def radamsa(data):
    if(config.debug):
        print("\n[MUTATOR] radamsa\n")

    radamsa = pyradamsa.Radamsa()
    data = bytearray(radamsa.fuzz(data))

    return data
