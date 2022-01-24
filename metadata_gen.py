import cbor
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def hexdump(data):
    for i in range(len(data)):
        x = data[i]
        end = '\n' if i + 1 >= 16 and (i + 1) % 16 == 0 else ''
        print(f'0x{x:02x}, ', end=end)


# Key generation:
# openssl genpkey -algorithm ED25519 > /tmp/key.priv
# openssl pkey -in /tmp/key.priv -noout -text
# ED25519 Private-Key:
# priv:
#     12:7d:73:f1:d3:b5:bc:08:63:7e:0c:fb:67:06:d6:
#     12:0e:3c:ce:90:69:87:4c:a7:0d:ce:f0:44:95:9a:
#     ec:02
# pub:
#     4a:d9:d7:fe:ba:04:b3:83:a1:9d:54:d0:66:1c:97:
#     69:58:13:b7:dc:24:29:09:94:c7:c7:f9:92:39:6e:
#     79:24

aik_key = Ed25519PrivateKey.from_private_bytes(bytes([
    0x12, 0x7D, 0x73, 0xF1, 0xD3, 0xB5, 0xBC, 0x08, 0x63, 0x7E, 0x0C, 0xFB, 0x67, 0x06, 0xD6, 0x12,
    0x0E, 0x3C, 0xCE, 0x90, 0x69, 0x87, 0x4C, 0xA7, 0x0D, 0xCE, 0xF0, 0x44, 0x95, 0x9A, 0xEC, 0x02
]))

meta = {
    'version': 1,
    'mac': [1, 2, 3, 4, 5, 6],
    'sn': [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x10, 0x13, 0xee],
    'EK_hash': {
        'id': 0,
        'hash': [
            0xbb, 0x36, 0x3d, 0xff, 0xc0, 0x51, 0x2e, 0xf9,
            0xf6, 0xc8, 0xce, 0xae, 0x22, 0xe2, 0x41, 0x1c,
            0xdd, 0x22, 0x37, 0x0f, 0xec, 0x0d, 0x47, 0xf6,
            0xca, 0xa8, 0x1e, 0xb5, 0xd7, 0x35, 0x7e, 0xaf
        ]
    }
}

metadata_encoded = cbor.dumps(meta)
signature = aik_key.sign(metadata_encoded)

with_sig = {
    'encoded_metadata': metadata_encoded,
    'signature': signature
}

hexdump(cbor.dumps(with_sig))
