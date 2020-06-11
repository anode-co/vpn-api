# You may redistribute this program and/or modify it under the terms of
# the GNU General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from hashlib import sha512;
import sys

# see util/Base32.h
def Base32_decode(input):
    output = bytearray(len(input));
    numForAscii = [
        99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
        99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
        99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9,99,99,99,99,99,99,
        99,99,10,11,12,99,13,14,15,99,16,17,18,19,20,99,
        21,22,23,24,25,26,27,28,29,30,31,99,99,99,99,99,
        99,99,10,11,12,99,13,14,15,99,16,17,18,19,20,99,
        21,22,23,24,25,26,27,28,29,30,31,99,99,99,99,99,
    ];

    outputIndex = 0;
    nextByte = 0;
    bits = 0;

    if sys.version_info[0] < 3:
      input = [ ord(c) for c in input ]
    for o in input:
        if (o & 0x80): raise ValueError;
        b = numForAscii[o];
        if (b > 31): raise ValueError("bad character " + chr(o));

        nextByte |= (b << bits);
        bits += 5;

        if (bits >= 8):
            output[outputIndex] = nextByte & 0xff;
            outputIndex += 1;
            bits -= 8;
            nextByte >>= 8;

    if (bits >= 5 or nextByte):
        raise ValueError("bits is " + str(bits) + " and nextByte is " + str(nextByte));

    return bytearray(output[:outputIndex]);


def PublicToIp6_convert(pubKey):
    #pubKey = pubKey.encode('ascii')
    if pubKey[-2:] != b'.k':
        raise ValueError("key does not end with .k")

    keyBytes = Base32_decode(pubKey[:-2])
    hashOne = sha512(keyBytes).digest()
    hashTwo = sha512(hashOne).hexdigest()

    return ":".join([hashTwo[i:i+4] for i in range(0, 32, 4)])
