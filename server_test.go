package socks5

import "testing"
import "net"

func TestNewToSavePrefixes(t *testing.T) {
  prefix, _, _ := net.ParseCIDR("::1/128")
  prefixes := []net.IP{prefix}
  server := New(prefixes)

  if len(server.Prefixes) == 1 {
    actual_prefixes := server.Prefixes
    actual_prefix := actual_prefixes[0]
    if actual_prefix != prefix {
      t.Error("Expected IP ::1/128")
    }
  } else {
    t.Error("len != 1")
  }
}
