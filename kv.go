package delphi

import (
	"encoding/json"
	"fmt"
	"iter"
	"slices"
	"strings"
)

// a KV is a simple map with some super powers useful to us
type KV map[string]string

func (kv KV) Set(keyspace string, key string, val string) {
	kv[fmt.Sprintf("%s/%s", keyspace, key)] = val
}

func (kv KV) Get(keyspace string, key string) string {
	return kv[fmt.Sprintf("%s/%s", keyspace, key)]
}

func (kv KV) MarshalBinary() ([]byte, error) {
	lines := make([]string, 0)
	for k, v := range kv.LexicalOrder() {
		lines = append(lines, k)
		lines = append(lines, v)
	}
	everything := strings.Join(lines, "\n")
	return []byte(everything), nil
}

func (kv *KV) UnmarshalBinary(b []byte) error {
	m := *kv
	everything := string(b)
	lines := strings.Split(everything, "\n")
	for i := 0; i < len(lines)/2; i = i + 2 {
		k := lines[i]
		v := lines[i+1]
		m[k] = v
	}
	return nil
}

// LexicolOrder ranges through a KV in lexical order
func (kv KV) LexicalOrder() iter.Seq2[string, string] {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return func(yield func(string, string) bool) {
		for _, k := range keys {
			v := kv[k]
			if !yield(k, v) {
				return
			}
		}
	}
}

func (kv KV) MarshalJSON() ([]byte, error) {
	return json.MarshalIndent(kv, "", "\t")
}
