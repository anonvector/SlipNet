package main

import "testing"

func TestFormatDNSAddr_EmptyResolvers(t *testing.T) {
	cases := []struct {
		name      string
		resolvers string
		transport string
		want      string
	}{
		{"empty resolvers", "", "udp", ""},
		{"empty entry in list", ",1.1.1.1", "udp", "1.1.1.1:53"},
		{"trailing comma", "8.8.8.8,", "udp", "8.8.8.8:53"},
		{"valid single", "8.8.8.8", "udp", "8.8.8.8:53"},
		{"valid with port", "8.8.8.8:5353", "udp", "8.8.8.8:5353"},
		{"valid multi", "8.8.8.8,1.1.1.1", "udp", "8.8.8.8:53,1.1.1.1:53"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Profile{Resolvers: tc.resolvers, DNSTransport: tc.transport}
			got := formatDNSAddr(p)
			if got != tc.want {
				t.Errorf("formatDNSAddr(%q) = %q, want %q", tc.resolvers, got, tc.want)
			}
		})
	}
}
