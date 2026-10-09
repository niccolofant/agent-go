package idl

import "errors"

var ErrUninhabitedRecord = errors.New("cannot decode uninhabited recursive record")

// HasMandatoryRecordCycle reports a mandatory record cycle classified by
// MarkUninhabitedRecords. No finite value can inhabit such a record. An absent
// optional, empty vector or unchosen variant containing it is still valid.
// False does not imply inhabited: other types, such as empty, can prevent values.
func (record RecordType) HasMandatoryRecordCycle() bool { return record.uninhabited }

// MarkUninhabitedRecords classifies a resolved wire type table in linear time,
// without recursion. Every record dependency must occur in types. Re-run after
// modifying record fields. Classification mutates the graph; do not classify or
// modify the graph concurrently with decoding.
// Byte-consuming opt/vec/variant edges are deliberately not record dependencies.
func MarkUninhabitedRecords(types []Type) {
	type node struct {
		record  *RecordType
		pending int
		parents []int
	}
	indexes := make(map[*RecordType]int)
	var nodes []node
	for _, typ := range types {
		if record, ok := typ.(*RecordType); ok {
			if _, found := indexes[record]; !found {
				indexes[record] = len(nodes)
				nodes = append(nodes, node{record: record})
			}
		}
	}
	for i := range nodes {
		for _, field := range nodes[i].record.Fields {
			if record, ok := field.Type.(*RecordType); ok {
				if j, found := indexes[record]; found {
					nodes[i].pending++
					nodes[j].parents = append(nodes[j].parents, i)
				}
			}
		}
	}
	queue := make([]int, 0, len(nodes))
	for i := range nodes {
		if nodes[i].pending == 0 {
			queue = append(queue, i)
		}
	}
	for i := 0; i < len(queue); i++ {
		for _, parent := range nodes[queue[i]].parents {
			nodes[parent].pending--
			if nodes[parent].pending == 0 {
				queue = append(queue, parent)
			}
		}
	}
	// Nodes left after removing finite leaves are cycles or their mandatory
	// record ancestors. Neither can have a finite record value.
	for i := range nodes {
		nodes[i].record.uninhabited = nodes[i].pending != 0
	}
}
