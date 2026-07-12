package idl

import (
	"reflect"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// lowerFirstCharacter returns a copy of the string with the first character in lower case.
// e.g. "UserName" -> "userName"
func lowerFirstCharacter(s string) string {
	if len(s) == 0 {
		return s
	}
	if s[0] < 'A' || s[0] > 'Z' {
		if s[0] < utf8.RuneSelf {
			return s
		}
		r, size := utf8.DecodeRuneInString(s)
		lower := unicode.ToLower(r)
		if lower == r {
			return s
		}
		return string(lower) + s[size:]
	}
	b := []byte(s)
	b[0] += 'a' - 'A'
	return string(b)
}

type Tag struct {
	// Name is the name of the field in the struct.
	Name        string
	VariantType bool
	TupleType   bool
}

func ParseTags(field reflect.StructField) Tag {
	icTag := field.Tag.Get("ic")
	if icTag == "" {
		return Tag{
			Name: lowerFirstCharacter(field.Name),
		}
	}
	var t Tag
	tags := strings.Split(icTag, ",")
	if len(tags) != 0 {
		t.Name = tags[0]
		for _, option := range tags[1:] {
			switch option {
			case "variant":
				t.VariantType = true
			case "tuple":
				t.TupleType = true
			default:
				// ignore unknown options
			}
		}
	}
	return t
}

type structFieldLookup struct {
	byName map[string]int
}

var structFieldLookupCache sync.Map // map[reflect.Type]*structFieldLookup

// lookupStructField resolves both source field names and the numeric field IDs
// carried by decoded Candid records. Reflection metadata is immutable, so each
// Go struct type pays tag parsing and Candid hashing only once.
func lookupStructField(t reflect.Type, name string) (int, bool) {
	v, ok := structFieldLookupCache.Load(t)
	if !ok {
		built := buildStructFieldLookup(t)
		v, _ = structFieldLookupCache.LoadOrStore(t, built)
	}
	i, ok := v.(*structFieldLookup).byName[lowerFirstCharacter(name)]
	return i, ok
}

func buildStructFieldLookup(t reflect.Type) *structFieldLookup {
	lookup := &structFieldLookup{byName: make(map[string]int, 2*t.NumField())}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		name := ParseTags(field).Name
		if _, exists := lookup.byName[name]; !exists {
			lookup.byName[name] = i
		}
		hash := strconv.FormatUint(uint64(hashUint32(name)), 10)
		if _, exists := lookup.byName[hash]; !exists {
			lookup.byName[hash] = i
		}
	}
	return lookup
}
