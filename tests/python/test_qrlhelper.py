# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


from __future__ import print_function

from unittest import TestCase

from pyqrllib import pyqrllib


class TestHelper(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestHelper, self).__init__(*args, **kwargs)

    def test_empty(self):
        self.assertFalse(pyqrllib.QRLHelper.addressIsValid(b''))

    # Multi-sig regression. This is the binding QRL actually calls:
    # MultiSigAddressState.address_is_valid() delegates to QRLHelper, so when
    # v1.3.0's descriptor hardening rejected signature type 1, every multi-sig
    # address on the network became invalid.
    MULTI_SIG_ADDRESS = ('11000005bc07de22117e835d760a8081d91ba50eac3b4f12'
                         '26bae23215ad3f5034d45ed5d5f2a7')

    def test_multi_sig_address_is_valid(self):
        address = bytes(pyqrllib.hstr2bin(self.MULTI_SIG_ADDRESS))
        self.assertEqual(39, len(address))       # 3 descriptor + 32 hash + 4 checksum
        self.assertEqual(0x11, address[0])       # signature type 1 | SHAKE_128
        self.assertTrue(pyqrllib.QRLHelper.addressIsValid(address))

    def test_multi_sig_address_checksum_still_enforced(self):
        corrupted = bytearray(pyqrllib.hstr2bin(self.MULTI_SIG_ADDRESS))
        corrupted[-1] ^= 0xFF
        self.assertFalse(pyqrllib.QRLHelper.addressIsValid(bytes(corrupted)))

    def test_multi_sig_reserved_byte_still_enforced(self):
        tampered = bytearray(pyqrllib.hstr2bin(self.MULTI_SIG_ADDRESS))
        tampered[2] = 1
        self.assertFalse(pyqrllib.QRLHelper.addressIsValid(bytes(tampered)))

    def test_unknown_signature_type_still_rejected(self):
        tampered = bytearray(pyqrllib.hstr2bin(self.MULTI_SIG_ADDRESS))
        tampered[0] = 0x21                       # signature type 2
        self.assertFalse(pyqrllib.QRLHelper.addressIsValid(bytes(tampered)))
