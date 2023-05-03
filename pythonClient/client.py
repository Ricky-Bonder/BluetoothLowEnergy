import pygatt
import time
adapter = pygatt.BLEDevice('00:1A:7D:DA:71:15')
try:
    adapter.start()
    adapter.scan(timeout=5)
    device = adapter.connect('00:1A:7D:DA:71:15',address_type=pygatt.BLEAddressType.public)
    characteristic = "12346677-0000-1000-8000-00805F9B34FB"
    device.char_write_handle(characteristic, bytearray([0x00]), wait_for_response=True)
    time.sleep(2)
    value = device.char_read_handle(characteristic)
    print(value)
finally:
    adapter.stop()