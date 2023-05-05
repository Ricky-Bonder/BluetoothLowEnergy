import bleak
import asyncio
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
import time
import base64

def device_sort(device):
    return device.address

async def connect():
    ble_server = None
    KEY_EXCHANGE_CHAR_UUID = "12346677-0000-1000-8000-00805F9B34FB"

    try:
         devices = await bleak.BleakScanner.discover()
    except bleak.exc.BleakDBusError as e:
        if str(e) == '[org.bluez.Error.NotReady] Resource Not Ready':
            raise RuntimeError('Bluetooth is not ready. Maybe try `bluetoothctl power on`?')
        raise
    devices.sort(key=device_sort)
    print('==== BLE Discovery results ====')
    print('{0: >4} {1: <33} {2: <12}'.format(
        'S.N.', 'Name', 'Address'))
    for i, _ in enumerate(devices):
        print('[{0: >2}] {1: <33} {2: <12}'.format(i + 1, devices[i].name or 'Unknown', devices[i].address))
        if devices[i].name == 'RickBLETest':
            ble_server = devices[i].address
            print('Found device of choice:',devices[i].name)



    public_key_base64 = generate_key_pair()


    print('Connecting...')
    device = bleak.BleakClient(ble_server, timeout=100)
    
    await device.connect()
    

    print('Connected, writing public key in char...')
    await device.write_gatt_char(KEY_EXCHANGE_CHAR_UUID, public_key_base64)

    print('Written public key:', public_key_base64)
    await device.disconnect()

def generate_key_pair():
    # Generate a private key
    private_key = X25519PrivateKey.generate()

    # Derive the public key from the private key
    public_key = private_key.public_key()

    # Print the private and public keys in PEM format
    # print("Private key (PEM format):")
    # print(private_key.private_bytes(
    #     encoding = serialization.Encoding.PEM,
    #     format = serialization.PrivateFormat.PKCS8,
    #     encryption_algorithm = serialization.NoEncryption()
    # ))

    # print("Public key (PEM format):")
    # print(public_key.public_bytes(
    #     encoding = serialization.Encoding.PEM,
    #     format = serialization.PublicFormat.SubjectPublicKeyInfo
    # ))

    public_key_bytes = public_key.public_bytes(
        encoding = serialization.Encoding.Raw,
        format = serialization.PublicFormat.Raw
    )
    
    # Returns the public key encoded to be written in the BLE characteristic
    return base64.b64encode(public_key_bytes)

async def main():
    await connect()

if __name__ == '__main__':
    asyncio.run(main())