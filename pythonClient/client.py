
from time import sleep
import pydbus
from gi.repository import GLib

DEVICE_ADDR = '00:1A:7D:DA:71:15' #  micro:bit address
BTN_A_STATE = '12346677-0000-1000-8000-00805F9B34FB'

# DBus object paths
BLUEZ_SERVICE = 'org.bluez'
ADAPTER_PATH = '/org/bluez/hci0'
# device_path = f"{ADAPTER_PATH}/dev_{DEVICE_ADDR.replace(':', '_')}"
device_path = "/org/bluez/hci0/dev_00_1A_7D_DA_71_15"

# setup dbus
bus = pydbus.SystemBus()
mngr = bus.get(BLUEZ_SERVICE, '/')
# adapter = bus.get(BLUEZ_SERVICE, ADAPTER_PATH) 
device = bus.get(BLUEZ_SERVICE, device_path)

device.Connect()

while not device.ServicesResolved:
    sleep(0.5)

def get_characteristic_path(dev_path, uuid):
    """Look up DBus path for characteristic UUID"""
    mng_objs = mngr.GetManagedObjects()
    for path in mng_objs:
        chr_uuid = mng_objs[path].get('org.bluez.GattCharacteristic1', {}).get('UUID')
        if path.startswith(dev_path) and chr_uuid == uuid.casefold():
           return path

# Characteristic DBus information
btn_a_path = get_characteristic_path(device._path, BTN_A_STATE)
btn_a = bus.get(BLUEZ_SERVICE, btn_a_path)
# Read button A without event loop notifications
print(btn_a.ReadValue({}))

# Enable eventloop for notifications
def btn_handler(iface, prop_changed, prop_removed):
    """Notify event handler for button press"""
    if 'Value' in prop_changed:
        new_value = prop_changed['Value']
        print(f"Button A state: {new_value}")
        print(f'As byte: {bytes(new_value)}')
        print(f'As bytearray: {bytearray(new_value)}')
        print(f'As int: {int(new_value[0])}')
        print(f'As bool: {bool(new_value[0])}')

mainloop = GLib.MainLoop()
btn_a.onPropertiesChanged = btn_handler
btn_a.StartNotify()
try:
    mainloop.run()
except KeyboardInterrupt:
    mainloop.quit()
    btn_a.StopNotify()
    device.Disconnect()