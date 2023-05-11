import bleak
import asyncio
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
import base64


private_key = None
def device_sort(device):
    return device.address

async def connect():
    global private_key
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
    
    handshakeData = bytes("S0,", "utf-8") + public_key_base64


    print('Connecting...')
    device = bleak.BleakClient(ble_server, timeout=100)
    
    await device.connect()

    print('Connected, writing public key in char...')
    await device.write_gatt_char(KEY_EXCHANGE_CHAR_UUID, handshakeData)
    
    # Subscribe to notifications from the characteristic
    async with bleak.BleakClient(ble_server) as device:
        await device.start_notify(KEY_EXCHANGE_CHAR_UUID, handle_notification)  
    # Wait for a notification from the characteristic
    notification = await asyncio.wait_for(device.read_gatt_char(KEY_EXCHANGE_CHAR_UUID), timeout=5.0)
        

    print('Written public key:', public_key_base64)
    await device.disconnect()

async def handle_notification(sender, data):
    # Split the notification data into a list of three items
    # Expected structure: S1,<base64(chiave pubblica)>,<base64(random)>
    handshake_structure = data.split(b",")
    if len(handshake_structure) != 3:
        # Handle the case where the notification data is not in the expected format
        return

    # Decode the second and third items from base64
    ahu_public_key = base64.b64decode(handshake_structure[1]).decode()
    ahu_random_iv = base64.b64decode(handshake_structure[2]).decode()
    
    X25519PublicKey.from_public_bytes(ahu_public_key)
    # WIP: i want to call the following on my private_key, not the class ??
    shared_secret = X25519PrivateKey.generate(ahu_public_key)
    
    # Perform the XOR operation between the shared key and the SHA-256 digest
    result = bytes([x ^ y for x, y in zip(shared_secret, ahu_random_iv)])

    print(result)
    
    

def generate_key_pair():
    # Generate a private key
    global private_key
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


    # Ensure the public key is 32 bytes by padding or truncating it
    if len(public_key_bytes) < 32:
        public_key_bytes += b'\x00' * (32 - len(public_key_bytes))
    elif len(public_key_bytes) > 32:
        public_key_bytes = public_key_bytes[:32]
    
    # Returns the public key encoded to be written in the BLE characteristic
    return base64.b64encode(public_key_bytes)

async def main():
    await connect()

if __name__ == '__main__':
    asyncio.run(main())