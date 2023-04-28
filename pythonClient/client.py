import sys
sys.path.append('/path/to/bluepy')

from bluepy.btle import Peripheral, UUID

# UUID of the service and characteristic
SERVICE_UUID = "2342233-0000-1000-8000-00805F9B34FB"
CHARACTERISTIC_UUID = "12346677-0000-1000-8000-00805F9B34FB"

# Base64 encoded public key
PUBLIC_KEY_BASE64 = "YOUR_BASE64_ENCODED_PUBLIC_KEY_GOES_HERE"

# Connect to the GATT server
peripheral = Peripheral("00:1a:7d:da:71:15")

# Find the service and characteristic
service = peripheral.getServiceByUUID(UUID(SERVICE_UUID))
char = service.getCharacteristics(UUID(CHARACTERISTIC_UUID))[0]

# Write the public key to the characteristic
char.write(PUBLIC_KEY_BASE64.encode())

# Disconnect from the GATT server
peripheral.disconnect()