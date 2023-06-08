package main

import (
	"testing"
)

func TestParseRemote(t *testing.T) {
	cases := make(map[string]SSHRemote)

	cases["localhost:22"] = SSHRemote{Host: "localhost", Port: 22}
	cases["localhost"] = SSHRemote{Host: "localhost", Port: -1}
	cases["root@localhost"] = SSHRemote{Username: "root", Host: "localhost", Port: -1}
	cases["root@localhost:22"] = SSHRemote{Username: "root", Host: "localhost", Port: 22}

	for input, expected := range cases {
		actual, err := parseSSHRemote(input)
		if err != nil {
			t.Errorf("[FAILED] Unexpected error: %s", err)
		}
		if !actual.IsEqual(expected) {
			t.Errorf("[FAILED] Failed to parse %s, Expected %v, got %v", input, expected, actual)
		} else {
			t.Logf("[PASSED] Parsed %s as %v", input, actual)
		}
	}
}

func (r SSHRemote) IsEqual(other SSHRemote) bool {
	return r.Host == other.Host && r.Port == other.Port && r.Username == other.Username
}
