#Copyright (c) 2011, Leapfrog Direct Response, LLC
#All rights reserved.
#
#Redistribution and use in source and binary forms, with or without
#modification, are permitted provided that the following conditions are met:
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of the Leapfrog Direct Response, LLC, including
#      its subsidiaries and affiliates nor the names of its
#      contributors, may be used to endorse or promote products derived
#      from this software without specific prior written permission.
#
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL LEAPFROG DIRECT
#RESPONSE, LLC, INCLUDING ITS SUBSIDIARIES AND AFFILIATES, BE LIABLE
#FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
#BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
#OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
#IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import random
import string
import itertools
from copy import copy
from functools import partial
from rstr.xeger import Xeger


ALPHABETS = {'printable': string.printable,
             'letters': string.ascii_letters,
             'uppercase': string.ascii_uppercase,
             'lowercase': string.ascii_lowercase,
             'digits': string.digits,
             'punctuation': string.punctuation,
             'nondigits': string.ascii_letters + string.punctuation,
             'nonletters': string.digits + string.punctuation,
             'whitespace': string.whitespace,
             'nonwhitespace': string.printable.strip(),
             'normal': string.ascii_letters + string.digits + ' ',
             'word': string.ascii_letters + string.digits + '_',
             'nonword': ''.join(set(string.printable)
                                .difference(string.ascii_letters +
                                            string.digits + '_')),
             'postalsafe': string.ascii_letters + string.digits + ' .-#/',
             'urlsafe': string.ascii_letters + string.digits + '-._~',
             'domainsafe': string.ascii_letters + string.digits + '-'
            }


class RstrBase(object):
    """Create random strings from a variety of alphabets.

    The alphabets for printable(), uppercase(), lowercase(), digits(), and
    punctuation() are equivalent to the constants by those same names in the
    standard library string module.

    nondigits() uses an alphabet of string.letters + string.punctuation

    nonletters() uses an alphabet of string.digits + string.punctuation

    nonwhitespace() uses an alphabet of string.printable.strip()

    normal() uses an alphabet of string.letters + string.digits + ' ' (the
    space character)

    postalsafe() is based on USPS Publication 28 - Postal Addressing Standards:
    http://pe.usps.com/text/pub28/pub28c2.html
    The characters allowed in postal addresses are letters and digits, periods,
    slashes, the pound sign, and the hyphen.

    urlsafe() uses an alphabet of unreserved characters safe for use in URLs.
    From section 2.3 of RFC 3986: "Characters that are allowed in a URI but
    do not have a reserved purpose are called unreserved. These include
    uppercase and lowercase letters, decimal digits, hyphen, period,
    underscore, and tilde.

    domainsafe() uses an alphabet of characters allowed in hostnames, and
    consequently, in internet domains: letters, digits, and the hyphen.

    """
    def __init__(self, **custom_alphabets):
        super(RstrBase, self).__init__()
        self._alphabets = copy(ALPHABETS)
        for alpha_name, alphabet in custom_alphabets.items():
            self.add_alphabet(alpha_name, alphabet)

    def add_alphabet(self, alpha_name, characters):
        """Add an additional alphabet to an Rstr instance and make it available
        via method calls.

        """
        self._alphabets[alpha_name] = characters

    def __getattr__(self, attr):
        if attr in self._alphabets:
            return partial(self.rstr, self._alphabets[attr])
        else:
            message = "Rstr instance has no attribute: {0}".format(attr)
            raise AttributeError(message)

    def rstr(self, alphabet, start_range=None,
             end_range=None, include='', exclude=''):
        """Generate a random string containing elements from 'alphabet'

        By default, rstr() will return a string between 1 and 10 characters.
        You can specify a second argument to get an exact length of string.

        If you want a string in a range of lengths, specify the start and end
        of that range as the second and third arguments.

        If you want to make certain that particular characters appear in the
        generated string, specify them as "include".

        If you want to *prevent* certain characters from appearing, pass them
        as 'exclude'.

        """
        popul = [char for char in list(alphabet) if char not in list(exclude)]

        if end_range is None:
            if start_range is None:
                start_range, end_range = (1, 10)
            else:
                k = start_range

        if end_range:
            k = random.randint(start_range, end_range)

        result = sample_wr(popul, k) + list(include)
        random.shuffle(result)
        return ''.join(result)


class Rstr(RstrBase, Xeger):
    def init(self, **alphabets):
        super(Rstr, self).__init__(**alphabets)

default_instance = Rstr()


def sample_wr(population, k):
    """Samples k random elements (with replacement) from a population"""
    return [random.choice(population) for i in itertools.repeat(None, k)]