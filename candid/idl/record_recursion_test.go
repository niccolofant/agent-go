package idl

import "testing"

func TestMarkUninhabitedRecords(t *testing.T) {
	a, b, parent, leaf := &RecordType{}, &RecordType{}, &RecordType{}, &RecordType{}
	a.Fields = []FieldType{{Type: b}, {Type: leaf}}
	b.Fields = []FieldType{{Type: a}}
	parent.Fields = []FieldType{{Type: a}, {Type: a}}
	guarded := &RecordType{Fields: []FieldType{{Type: NewOptionalType(a)}}}
	guarded.Fields = append(guarded.Fields, FieldType{Type: NewOptionalType(guarded)})
	MarkUninhabitedRecords([]Type{a, b, parent, leaf, guarded, a})
	for _, r := range []*RecordType{a, b, parent} {
		if !r.HasMandatoryRecordCycle() {
			t.Fatal("cycle/ancestor not marked")
		}
	}
	if leaf.HasMandatoryRecordCycle() || guarded.HasMandatoryRecordCycle() {
		t.Fatal("finite record marked")
	}
	b.Fields = nil
	MarkUninhabitedRecords([]Type{a, b, parent, leaf, guarded})
	for _, r := range []*RecordType{a, b, parent, leaf, guarded} {
		if r.HasMandatoryRecordCycle() {
			t.Fatal("classification not reset")
		}
	}
}
