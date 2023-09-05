package bacnet

type PropertyValue struct {
	Identifier PropertyIdentifier
	Arrayindex *uint32
	Value      uint32
	Priority   uint32
}
