import pygatt
adapter = pygatt.backends.GATTToolBackend()
#adapter = pygatt.BGAPIBackend()
adapter.start()
adapter.scan(timeout=1)
device = adapter.connect('00:1A:7D:DA:71:15',address_type=pygatt.BLEAddressType.public)
characteristic = "12346677-0000-1000-8000-00805F9B34FB"
device.char_write(characteristic, bytearray([0x00]), wait_for_response=True)
value = device.char_read(characteristic)
print(value)
adapter.stop()