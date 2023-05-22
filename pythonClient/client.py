import bleak
import asyncio
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os
import time
from Crypto.Cipher import AES
from Crypto.Util import Counter

g_private_key = None
g_private_key = None
g_verification_token = None

def device_sort(device):
    return device.address

async def connect():
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
            for char in service.characteristics:
                if char.uuid == KEY_EXCHANGE_CHAR_UUID:
                    print("found handshake char!")                    
                    
                    if "write" in char.properties:
                        try:
                            await device.write_gatt_char(char.handle, handshake_data, True)
                            print('Written public key:', public_key_base64)
                        except Exception as e:
                            print(str(e).encode())
                    
                    print("\t[Characteristic] {0}: (Handle: {1}) ({2})".format(
                        char.uuid,
                        char.handle,
                        ",".join(char.properties)
                    ))

                    server_response = bytes(await read_server_response(device, char))

                    if server_response != bytes(): 
                        print("\t[Characteristic] {0}: (Handle: {1}) ({2}) | Name: {3}, Value: {4} ".format(
                            char.uuid,
                            char.handle,
                            ",".join(char.properties),
                            char.description,
                            str(server_response)
                        ))
                        
                        generate_session_key(server_response)
                        
                        encoded_verification_token = base64.b64encode(bytes("S2,", "utf-8") + generate_aes_verification_token())
                        try:
                            await device.write_gatt_char(char.handle, encoded_verification_token, False)
                            print('Written verification token:', encoded_verification_token)
                        except Exception as e:
                            print(str(e).encode())
                        
                        # read S3 server response
                        server_response = bytes(await read_server_response(device, char))
                        print("S3 received: ",str(server_response))

    await device.disconnect()
    
    
async def read_server_response(device, char):
    server_response = bytes()          
    timeout = time.time() + 10  # 10 seconds from now
    max_retries = 5
    while True:
        await asyncio.sleep(0.1)    
    
        if "read" in char.properties:
            try:
                server_response = bytes(await device.read_gatt_char(char.handle))
                return server_response
            except Exception as e:
                server_response = str(e).encode()
                return
                                        
        if server_response != bytes() or max_retries == 0 or time.time() > timeout:
            break
        max_retries = max_retries - 1

def generate_session_key(data):
    global g_session_key
    global ahu_public_key
    global ahu_random_iv
    handshake_structure = str(data).split(",")
    s1 = handshake_structure[0]
    s1 = s1[2:]
    server_pub_key = handshake_structure[1]
    pop = handshake_structure[2]
    pop = pop[:-1]
    print("decoded handshake structure", s1, server_pub_key, pop)
        
    # Split the notification data into a list of three items
    # Expected structure: S1,<base64(server_public_key)>,<base64(random)>
    if len(handshake_structure) != 3:
        # Handle the case where the notification data is not in the expected format
        print("len != 3, data:", str(data))
        return
    
    # Decode the second and third items from base64
    ahu_public_key = base64.b64decode(server_pub_key)
    ahu_random_iv = base64.b64decode(pop)
    
   
    private_key = X25519PrivateKey.generate()
    # public_key = private_key.public_key()
    shared_secret = private_key.exchange(X25519PublicKey.from_public_bytes(ahu_public_key))
    
    # Perform the XOR operation between the shared key and the SHA-256 digest 
    g_session_key = bytes([x ^ y for x, y in zip(shared_secret, ahu_random_iv)])

    print("generated session key:",g_session_key)
    
    
def aes_ctr_encrypt(key, data, nonce):
    ctr = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return aes.encrypt(data)
    
def generate_aes_verification_token():
    global g_session_key
    global ahu_public_key
    global ahu_random_iv

    # Generate a verification token by encrypting the client public key with the AES ciphe
    client_token_verify = aes_ctr_encrypt(g_session_key, ahu_public_key, ahu_random_iv)
    
    print("Verification token: ",client_token_verify)
    return client_token_verify

def generate_key_pair():
    # Generate a private key
    global g_private_key
    global public_key
    g_private_key = X25519PrivateKey.generate()

    # Derive the public key from the private key
    public_key = g_private_key.public_key()

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