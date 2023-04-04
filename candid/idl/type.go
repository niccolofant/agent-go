package idl

import (
	"bytes"
	"fmt"
)

var (
	nullType      int64 = -1  // 0x7f
	boolType      int64 = -2  // 0x7e
	natType       int64 = -3  // 0x7d
	intType       int64 = -4  // 0x7c
	natXType      int64 = -5  // 0x7b-0x78
	intXType      int64 = -9  // 0x77-0x73
	floatXType    int64 = -13 // 0x72
	textType      int64 = -15 // 0x71
	reservedType  int64 = -16 // 0x70
	emptyType     int64 = -17 // 0x6f
	optType       int64 = -18 // 0x6e
	vecType       int64 = -19 // 0x6d
	recType       int64 = -20 // 0x6c
	varType       int64 = -21 // 0x6b
	funcType      int64 = -22 // 0x6a
	serviceType   int64 = -23 // 0x69
	principalType int64 = -24 // 0x68
)

// EqualIDLs returns true if the two types are equal.
func EqualIDLs(a, b Type) bool {
	return a.String() == b.String()
}

func idlString(typ int64) string {
	switch typ {
	case nullType:
		return "null"
	case boolType:
		return "bool"
	case natType:
		return "nat"
	case intType:
		return "int"
	case natXType:
		return "nat8"
	case natXType - 1:
		return "nat16"
	case natXType - 2:
		return "nat32"
	case natXType - 3:
		return "nat64"
	case intXType:
		return "int8"
	case intXType - 1:
		return "int16"
	case intXType - 2:
		return "int32"
	case intXType - 3:
		return "int64"
	case floatXType:
		return "float32"
	case floatXType - 1:
		return "float64"
	case textType:
		return "text"
	case reservedType:
		return "reserved"
	case emptyType:
		return "empty"
	case optType:
		return "opt"
	case vecType:
		return "vec"
	case recType:
		return "rec"
	case varType:
		return "var"
	case funcType:
		return "func"
	case serviceType:
		return "service"
	case principalType:
		return "principal"
	default:
		return "unknown"
	}
}

type PrimType interface {
	prim()
}

type Type interface {
	// AddTypeDefinition adds itself to the definition table if it is not a primitive type.
	AddTypeDefinition(*TypeDefinitionTable) error

	// Decode decodes the value from the reader.
	Decode(*bytes.Reader) (any, error)

	// EncodeType encodes the type.
	EncodeType(*TypeDefinitionTable) ([]byte, error)

	// EncodeValue encodes the value.
	EncodeValue(v any) ([]byte, error)

	fmt.Stringer
}

func getType(t int64, tds []Type) (Type, error) {
	if t >= 0 {
		if int(t) >= len(tds) {
			return nil, fmt.Errorf("type index out of range: %d", t)
		}
		return tds[t], nil
	}

	switch t {
	case nullType:
		return new(NullType), nil
	case boolType:
		return new(BoolType), nil
	case natType:
		return new(NatType), nil
	case intType:
		return new(IntType), nil
	case natXType:
		return Nat8Type(), nil
	case natXType - 1:
		return Nat16Type(), nil
	case natXType - 2:
		return Nat32Type(), nil
	case natXType - 3:
		return Nat64Type(), nil
	case intXType:
		return Int8Type(), nil
	case intXType - 1:
		return Int16Type(), nil
	case intXType - 2:
		return Int32Type(), nil
	case intXType - 3:
		return Int64Type(), nil
	case floatXType:
		return Float32Type(), nil
	case floatXType - 1:
		return Float64Type(), nil
	case textType:
		return new(TextType), nil
	case reservedType:
		return new(ReservedType), nil
	case emptyType:
		return new(EmptyType), nil
	case principalType:
		return new(PrincipalType), nil
	default:
		if t < -24 {
			return nil, &FormatError{
				Description: "type: out of range",
			}
		}
		return nil, &FormatError{
			Description: "type: not primitive",
		}
	}
}

type primType struct{}

func (primType) AddTypeDefinition(_ *TypeDefinitionTable) error {
	return nil // No need to add primitive types to the type definition table.
}

func (primType) prim() {}
