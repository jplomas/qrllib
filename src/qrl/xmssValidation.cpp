// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include "xmssValidation.h"

#include <stdexcept>

namespace XmssValidation {

void hashFunction(eHashFunction value)
{
    switch (value) {
        case eHashFunction::SHA2_256:
        case eHashFunction::SHAKE_128:
        case eHashFunction::SHAKE_256:
            return;
    }
    throw std::invalid_argument("Unsupported XMSS hash function");
}

void addressFormat(eAddrFormatType value)
{
    if (value != eAddrFormatType::SHA256_2X) {
        throw std::invalid_argument("Unsupported XMSS address format");
    }
}

void height(uint8_t value)
{
    if (value < MIN_HEIGHT || value > MAX_HEIGHT || (value & 1U) != 0) {
        throw std::invalid_argument("XMSS height must be even and between 4 and 30");
    }
}

void wots(uint32_t value)
{
    // base_w consumes one byte in an integral number of log2(w)-bit digits.
    // These are the finite power-of-two values that satisfy that contract.
    if (value != 2 && value != 4 && value != 16 && value != 256) {
        throw std::invalid_argument("Unsupported XMSS WOTS parameter");
    }
}

void descriptorBytes(const std::vector<uint8_t>& bytes)
{
    if (bytes.size() != 3) {
        throw std::invalid_argument("Descriptor size should be 3 bytes");
    }
    if (bytes[2] != 0) {
        throw std::invalid_argument("XMSS descriptor reserved byte must be zero");
    }

    hashFunction(static_cast<eHashFunction>(bytes[0] & 0x0F));
    addressFormat(static_cast<eAddrFormatType>((bytes[1] >> 4) & 0x0F));

    // The XMSS tree rules below only apply to XMSS descriptors. QRL also uses
    // signature type 1 for multi-sig addresses, which have no tree and so
    // legitimately carry height 0 - validating those as XMSS rejected every
    // multi-sig address.
    const auto signatureType = static_cast<unsigned>(bytes[0] >> 4);
    const auto treeHeight = static_cast<uint8_t>((bytes[1] & 0x0F) << 1);
    switch (signatureType) {
    case 0:  // XMSS
        height(treeHeight);
        break;
    case 1:  // multi-sig
        if (treeHeight != 0) {
            throw std::invalid_argument("Multi-sig descriptor height must be zero");
        }
        break;
    default:
        throw std::invalid_argument("Unsupported signature type");
    }
}

uint32_t signatureCount(uint8_t value)
{
    height(value);
    return uint32_t{1} << value;
}

}  // namespace XmssValidation
