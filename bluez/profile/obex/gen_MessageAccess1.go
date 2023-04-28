// Code generated by go-bluetooth generator DO NOT EDIT.

package obex

import (
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/muka/go-bluetooth/bluez"
	"github.com/muka/go-bluetooth/props"
	"github.com/muka/go-bluetooth/util"
)

var MessageAccess1Interface = "org.bluez.obex.MessageAccess1"

// NewMessageAccess1 create a new instance of MessageAccess1
//
// Args:
// - objectPath: [Session object path]
func NewMessageAccess1(objectPath dbus.ObjectPath) (*MessageAccess1, error) {
	a := new(MessageAccess1)
	a.client = bluez.NewClient(
		&bluez.Config{
			Name:  "org.bluez.obex",
			Iface: MessageAccess1Interface,
			Path:  dbus.ObjectPath(objectPath),
			Bus:   bluez.SystemBus,
		},
	)
	a.Properties = new(MessageAccess1Properties)

	_, err := a.GetProperties()
	if err != nil {
		return nil, err
	}
	return a, nil
}

/*
MessageAccess1 Message Access hierarchy
*/
type MessageAccess1 struct {
	client                 *bluez.Client
	propertiesSignal       chan *dbus.Signal
	objectManagerSignal    chan *dbus.Signal
	objectManager          *bluez.ObjectManager
	Properties             *MessageAccess1Properties
	watchPropertiesChannel chan *dbus.Signal
}

// MessageAccess1Properties contains the exposed properties of an interface
type MessageAccess1Properties struct {
	lock sync.RWMutex `dbus:"ignore"`
}

// Lock access to properties
func (p *MessageAccess1Properties) Lock() {
	p.lock.Lock()
}

// Unlock access to properties
func (p *MessageAccess1Properties) Unlock() {
	p.lock.Unlock()
}

// Close the connection
func (a *MessageAccess1) Close() {
	a.unregisterPropertiesSignal()
	a.client.Disconnect()
}

// Path return MessageAccess1 object path
func (a *MessageAccess1) Path() dbus.ObjectPath {
	return a.client.Config.Path
}

// Client return MessageAccess1 dbus client
func (a *MessageAccess1) Client() *bluez.Client {
	return a.client
}

// Interface return MessageAccess1 interface
func (a *MessageAccess1) Interface() string {
	return a.client.Config.Iface
}

// GetObjectManagerSignal return a channel for receiving updates from the ObjectManager
func (a *MessageAccess1) GetObjectManagerSignal() (chan *dbus.Signal, func(), error) {

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

// ToMap convert a MessageAccess1Properties to map
func (a *MessageAccess1Properties) ToMap() (map[string]interface{}, error) {
	return props.ToMap(a), nil
}

// FromMap convert a map to an MessageAccess1Properties
func (a *MessageAccess1Properties) FromMap(props map[string]interface{}) (*MessageAccess1Properties, error) {
	props1 := map[string]dbus.Variant{}
	for k, val := range props {
		props1[k] = dbus.MakeVariant(val)
	}
	return a.FromDBusMap(props1)
}

// FromDBusMap convert a map to an MessageAccess1Properties
func (a *MessageAccess1Properties) FromDBusMap(props map[string]dbus.Variant) (*MessageAccess1Properties, error) {
	s := new(MessageAccess1Properties)
	err := util.MapToStruct(s, props)
	return s, err
}

// ToProps return the properties interface
func (a *MessageAccess1) ToProps() bluez.Properties {
	return a.Properties
}

// GetWatchPropertiesChannel return the dbus channel to receive properties interface
func (a *MessageAccess1) GetWatchPropertiesChannel() chan *dbus.Signal {
	return a.watchPropertiesChannel
}

// SetWatchPropertiesChannel set the dbus channel to receive properties interface
func (a *MessageAccess1) SetWatchPropertiesChannel(c chan *dbus.Signal) {
	a.watchPropertiesChannel = c
}

// GetProperties load all available properties
func (a *MessageAccess1) GetProperties() (*MessageAccess1Properties, error) {
	a.Properties.Lock()
	err := a.client.GetProperties(a.Properties)
	a.Properties.Unlock()
	return a.Properties, err
}

// SetProperty set a property
func (a *MessageAccess1) SetProperty(name string, value interface{}) error {
	return a.client.SetProperty(name, value)
}

// GetProperty get a property
func (a *MessageAccess1) GetProperty(name string) (dbus.Variant, error) {
	return a.client.GetProperty(name)
}

// GetPropertiesSignal return a channel for receiving udpdates on property changes
func (a *MessageAccess1) GetPropertiesSignal() (chan *dbus.Signal, error) {

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
func (a *MessageAccess1) unregisterPropertiesSignal() {
	if a.propertiesSignal != nil {
		a.propertiesSignal <- nil
		a.propertiesSignal = nil
	}
}

// WatchProperties updates on property changes
func (a *MessageAccess1) WatchProperties() (chan *bluez.PropertyChanged, error) {
	return bluez.WatchProperties(a)
}

func (a *MessageAccess1) UnwatchProperties(ch chan *bluez.PropertyChanged) error {
	return bluez.UnwatchProperties(a, ch)
}

/*
SetFolder 			Set working directory for current session, *name* may

	be the directory name or '..[/dir]'.
	Possible errors: org.bluez.obex.Error.InvalidArguments
			 org.bluez.obex.Error.Failed
*/
func (a *MessageAccess1) SetFolder(name string) error {
	return a.client.Call("SetFolder", 0, name).Store()
}

/*
ListFolders 			Returns a dictionary containing information about

	the current folder content.
	The following keys are defined:
		string Name : Folder name
	Possible filters: Offset and MaxCount
	Possible errors: org.bluez.obex.Error.InvalidArguments
			 org.bluez.obex.Error.Failed
*/
func (a *MessageAccess1) ListFolders(filter map[string]interface{}) ([]map[string]interface{}, error) {
	val0 := []map[string]interface{}{}
	err := a.client.Call("ListFolders", 0, filter).Store(&val0)
	return val0, err
}

/*
ListFilterFields 			Return all available fields that can be used in Fields

	filter.
	Possible errors: None
*/
func (a *MessageAccess1) ListFilterFields() ([]string, error) {
	val0 := []string{}
	err := a.client.Call("ListFilterFields", 0).Store(&val0)
	return val0, err
}

/*
ListMessages 			Returns an array containing the messages found in the

	given subfolder of the current folder, or in the
	current folder if folder is empty.
	Possible Filters: Offset, MaxCount, SubjectLength, Fields,
	Type, PeriodStart, PeriodEnd, Status, Recipient, Sender,
	Priority
	Each message is represented by an object path followed
	by a dictionary of the properties.
	Properties:
		string Subject:
			Message subject
		string Timestamp:
			Message timestamp
		string Sender:
			Message sender name
		string SenderAddress:
			Message sender address
		string ReplyTo:
			Message Reply-To address
		string Recipient:
			Message recipient name
		string RecipientAddress:
			Message recipient address
		string Type:
			Message type
			Possible values: "email", "sms-gsm",
			"sms-cdma" and "mms"
		uint64 Size:
			Message size in bytes
		boolean Text:
			Message text flag
			Specifies whether message has textual
			content or is binary only
		string Status:
			Message status
			Possible values for received messages:
			"complete", "fractioned", "notification"
			Possible values for sent messages:
			"delivery-success", "sending-success",
			"delivery-failure", "sending-failure"
		uint64 AttachmentSize:
			Message overall attachment size in bytes
		boolean Priority:
			Message priority flag
		boolean Read:
			Message read flag
		boolean Sent:
			Message sent flag
		boolean Protected:
			Message protected flag
	Possible errors: org.bluez.obex.Error.InvalidArguments
			 org.bluez.obex.Error.Failed
*/
func (a *MessageAccess1) ListMessages(folder string, filter map[string]interface{}) ([]Message, error) {
	val0 := []Message{}
	err := a.client.Call("ListMessages", 0, folder, filter).Store(&val0)
	return val0, err
}

/*
UpdateInbox
*/
func (a *MessageAccess1) UpdateInbox() error {
	return a.client.Call("UpdateInbox", 0).Store()
}