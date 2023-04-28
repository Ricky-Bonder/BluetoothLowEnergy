// Code generated by go-bluetooth generator DO NOT EDIT.

package advertisement_monitor

import (
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/muka/go-bluetooth/bluez"
	"github.com/muka/go-bluetooth/props"
	"github.com/muka/go-bluetooth/util"
)

var AdvertisementMonitorManager1Interface = "org.bluez.AdvertisementMonitorManager1"

// NewAdvertisementMonitorManager1 create a new instance of AdvertisementMonitorManager1
//
// Args:
// - objectPath: /org/bluez/{hci0,hci1,...}
func NewAdvertisementMonitorManager1(objectPath dbus.ObjectPath) (*AdvertisementMonitorManager1, error) {
	a := new(AdvertisementMonitorManager1)
	a.client = bluez.NewClient(
		&bluez.Config{
			Name:  "org.bluez",
			Iface: AdvertisementMonitorManager1Interface,
			Path:  dbus.ObjectPath(objectPath),
			Bus:   bluez.SystemBus,
		},
	)
	a.Properties = new(AdvertisementMonitorManager1Properties)

	_, err := a.GetProperties()
	if err != nil {
		return nil, err
	}
	return a, nil
}

/*
AdvertisementMonitorManager1 Advertisement Monitor Manager hierarchy
*/
type AdvertisementMonitorManager1 struct {
	client                 *bluez.Client
	propertiesSignal       chan *dbus.Signal
	objectManagerSignal    chan *dbus.Signal
	objectManager          *bluez.ObjectManager
	Properties             *AdvertisementMonitorManager1Properties
	watchPropertiesChannel chan *dbus.Signal
}

// AdvertisementMonitorManager1Properties contains the exposed properties of an interface
type AdvertisementMonitorManager1Properties struct {
	lock sync.RWMutex `dbus:"ignore"`

	/*
		SupportedFeatures This lists the features of advertisement monitoring
				supported by BlueZ.

				Possible values for features:

				"controller-patterns"
					If the controller is capable of performing
					advertisement monitoring by patterns, BlueZ
					would offload the patterns to the controller to
					reduce power consumption.
	*/
	SupportedFeatures []string

	/*
		SupportedMonitorTypes This lists the supported types of advertisement
				monitors. An application should check this before
				instantiate and expose an object of
				org.bluez.AdvertisementMonitor1.

				Possible values for monitor types:

				"or_patterns"
					Patterns with logic OR applied. With this type,
					property "Patterns" must exist and has at least
					one pattern.
	*/
	SupportedMonitorTypes []string
}

// Lock access to properties
func (p *AdvertisementMonitorManager1Properties) Lock() {
	p.lock.Lock()
}

// Unlock access to properties
func (p *AdvertisementMonitorManager1Properties) Unlock() {
	p.lock.Unlock()
}

// GetSupportedFeatures get SupportedFeatures value
func (a *AdvertisementMonitorManager1) GetSupportedFeatures() ([]string, error) {
	v, err := a.GetProperty("SupportedFeatures")
	if err != nil {
		return []string{}, err
	}
	return v.Value().([]string), nil
}

// GetSupportedMonitorTypes get SupportedMonitorTypes value
func (a *AdvertisementMonitorManager1) GetSupportedMonitorTypes() ([]string, error) {
	v, err := a.GetProperty("SupportedMonitorTypes")
	if err != nil {
		return []string{}, err
	}
	return v.Value().([]string), nil
}

// Close the connection
func (a *AdvertisementMonitorManager1) Close() {
	a.unregisterPropertiesSignal()
	a.client.Disconnect()
}

// Path return AdvertisementMonitorManager1 object path
func (a *AdvertisementMonitorManager1) Path() dbus.ObjectPath {
	return a.client.Config.Path
}

// Client return AdvertisementMonitorManager1 dbus client
func (a *AdvertisementMonitorManager1) Client() *bluez.Client {
	return a.client
}

// Interface return AdvertisementMonitorManager1 interface
func (a *AdvertisementMonitorManager1) Interface() string {
	return a.client.Config.Iface
}

// GetObjectManagerSignal return a channel for receiving updates from the ObjectManager
func (a *AdvertisementMonitorManager1) GetObjectManagerSignal() (chan *dbus.Signal, func(), error) {

	if a.objectManagerSignal == nil {
		if a.objectManager == nil {
			om, err := bluez.GetObjectManager()
			if err != nil {
				return nil, nil, err
			}
			a.objectManager = om
		}

		s, err := a.objectManager.Register()
		if err != nil {
			return nil, nil, err
		}
		a.objectManagerSignal = s
	}

	cancel := func() {
		if a.objectManagerSignal == nil {
			return
		}
		a.objectManagerSignal <- nil
		a.objectManager.Unregister(a.objectManagerSignal)
		a.objectManagerSignal = nil
	}

	return a.objectManagerSignal, cancel, nil
}

// ToMap convert a AdvertisementMonitorManager1Properties to map
func (a *AdvertisementMonitorManager1Properties) ToMap() (map[string]interface{}, error) {
	return props.ToMap(a), nil
}

// FromMap convert a map to an AdvertisementMonitorManager1Properties
func (a *AdvertisementMonitorManager1Properties) FromMap(props map[string]interface{}) (*AdvertisementMonitorManager1Properties, error) {
	props1 := map[string]dbus.Variant{}
	for k, val := range props {
		props1[k] = dbus.MakeVariant(val)
	}
	return a.FromDBusMap(props1)
}

// FromDBusMap convert a map to an AdvertisementMonitorManager1Properties
func (a *AdvertisementMonitorManager1Properties) FromDBusMap(props map[string]dbus.Variant) (*AdvertisementMonitorManager1Properties, error) {
	s := new(AdvertisementMonitorManager1Properties)
	err := util.MapToStruct(s, props)
	return s, err
}

// ToProps return the properties interface
func (a *AdvertisementMonitorManager1) ToProps() bluez.Properties {
	return a.Properties
}

// GetWatchPropertiesChannel return the dbus channel to receive properties interface
func (a *AdvertisementMonitorManager1) GetWatchPropertiesChannel() chan *dbus.Signal {
	return a.watchPropertiesChannel
}

// SetWatchPropertiesChannel set the dbus channel to receive properties interface
func (a *AdvertisementMonitorManager1) SetWatchPropertiesChannel(c chan *dbus.Signal) {
	a.watchPropertiesChannel = c
}

// GetProperties load all available properties
func (a *AdvertisementMonitorManager1) GetProperties() (*AdvertisementMonitorManager1Properties, error) {
	a.Properties.Lock()
	err := a.client.GetProperties(a.Properties)
	a.Properties.Unlock()
	return a.Properties, err
}

// SetProperty set a property
func (a *AdvertisementMonitorManager1) SetProperty(name string, value interface{}) error {
	return a.client.SetProperty(name, value)
}

// GetProperty get a property
func (a *AdvertisementMonitorManager1) GetProperty(name string) (dbus.Variant, error) {
	return a.client.GetProperty(name)
}

// GetPropertiesSignal return a channel for receiving udpdates on property changes
func (a *AdvertisementMonitorManager1) GetPropertiesSignal() (chan *dbus.Signal, error) {

	if a.propertiesSignal == nil {
		s, err := a.client.Register(a.client.Config.Path, bluez.PropertiesInterface)
		if err != nil {
			return nil, err
		}
		a.propertiesSignal = s
	}

	return a.propertiesSignal, nil
}

// Unregister for changes signalling
func (a *AdvertisementMonitorManager1) unregisterPropertiesSignal() {
	if a.propertiesSignal != nil {
		a.propertiesSignal <- nil
		a.propertiesSignal = nil
	}
}

// WatchProperties updates on property changes
func (a *AdvertisementMonitorManager1) WatchProperties() (chan *bluez.PropertyChanged, error) {
	return bluez.WatchProperties(a)
}

func (a *AdvertisementMonitorManager1) UnwatchProperties(ch chan *bluez.PropertyChanged) error {
	return bluez.UnwatchProperties(a, ch)
}

/*
RegisterMonitor 			This registers the root path of a hierarchy of

	advertisement monitors.
	The application object path together with the D-Bus
	system bus connection ID define the identification of
	the application registering advertisement monitors.
	Once a root path is registered by a client via this
	method, the client can freely expose/unexpose
	advertisement monitors without re-registering the root
	path again. After use, the client should call
	UnregisterMonitor() method to invalidate the
	advertisement monitors.
	Possible errors: org.bluez.Error.InvalidArguments
			 org.bluez.Error.AlreadyExists
			 org.bluez.Error.Failed
*/
func (a *AdvertisementMonitorManager1) RegisterMonitor(application dbus.ObjectPath) error {
	return a.client.Call("RegisterMonitor", 0, application).Store()
}

/*
UnregisterMonitor 			This unregisters a hierarchy of advertisement monitors

	that has been previously registered. The object path
	parameter must match the same value that has been used
	on registration. Upon unregistration, the advertisement
	monitor(s) should expect to receive Release() method as
	the signal that the advertisement monitor(s) has been
	deactivated.
	Possible errors: org.bluez.Error.InvalidArguments
			 org.bluez.Error.DoesNotExist
*/
func (a *AdvertisementMonitorManager1) UnregisterMonitor(application dbus.ObjectPath) error {
	return a.client.Call("UnregisterMonitor", 0, application).Store()
}