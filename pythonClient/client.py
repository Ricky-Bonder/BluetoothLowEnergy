import bleak
import asyncio
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os


private_key = None
def device_sort(device):
    return device.address

async def connect():
    global private_key
    ble_server = None
    KEY_EXCHANGE_CHAR_UUID = "12346677-0000-1000-8000-00805f9b34fb"

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
            ble_server = devices[i]
            print('Found device of choice:',devices[i].name)



    public_key_base64 = generate_key_pair()
    
    handshake_data = base64.b64encode(bytes("S0,", "utf-8") + public_key_base64)


    print('Connecting...')
    device = bleak.BleakClient(ble_server, timeout=1000)
    
    await device.connect()

    print('Connected, writing public key in char...')
    # await device.write_gatt_char(KEY_EXCHANGE_CHAR_UUID, handshake_data)
    
    # Subscribe to notifications from the characteristic
    async with bleak.BleakClient(ble_server) as device:
        await device.is_connected()
        for service in device.services:
            print("[Service] {0}: {1}".format(service.uuid, service.description))
            value = None
            for char in service.characteristics:
                if char.uuid == KEY_EXCHANGE_CHAR_UUID:
                    print("found handshake char!")
                    await device.start_notify(KEY_EXCHANGE_CHAR_UUID, handle_notification)
                    
                    if "write" in char.properties:
                        try:
                            value = bytes(await device.write_gatt_char(char.uuid, handshake_data, True))
                        except Exception as e:
                            value = str(e).encode()
                    
                    # await asyncio.sleep(5.0)    
                    
                    # if "read" in char.properties:
                    #     try:
                    #         value = bytes(await device.read_gatt_char(char.uuid))
                    #     except Exception as e:
                    #         value = str(e).encode()
                            
                            
                    print("\t[Characteristic] {0}: (Handle: {1}) ({2}) | Name: {3}, Value: {4} ".format(
                        char.uuid,
                        char.handle,
                        ",".join(char.properties),
                        char.description,
                        value
                    ))
                
                    
                    await asyncio.sleep(5.0)
                    await device.stop_notify(KEY_EXCHANGE_CHAR_UUID)
                    # Wait for a notification from the characteristic
                    # notification = await asyncio.wait_for(device.write_gatt_char(KEY_EXCHANGE_CHAR_UUID), timeout=5.0)
        
  
    
    print('Written public key:', public_key_base64)
    await device.disconnect()

def handle_notification(sender, data):
    print("received char notification:", str(data))
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
    global session_key 
    session_key = bytes([x ^ y for x, y in zip(shared_secret, ahu_random_iv)])

    print(session_key)
    
    
def generate_AES_verification_token():
    nonce = os.urandom(16)
    
    # Initialize the AES cipher in GCM mode with the session key and nonce
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce))

    # Generate a verification token by encrypting the client public key with the AES cipher
    encryptor = cipher.encryptor()
    ct = encryptor.update(public_key) + encryptor.finalize()
    tag = encryptor.tag

    # Concatenate the nonce and the ciphertext to create the verification token
    verification_token = nonce + ct + tag

    print(verification_token)

def generate_key_pair():
    # Generate a private key
    global private_key
    global public_key
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
    return public_key_bytes

async def main():
    await connect()

if __name__ == '__main__':
    asyncio.run(main())