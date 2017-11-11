package socks5

import (
  "bytes"
  "errors"
  "io"
  "log"
  "net"
  "os"
  "runtime"
  "strconv"
  "sync"
  "time"
  "math/rand"
  "encoding/binary"
)

type Server struct {
  Logger                               *log.Logger
  AuthNoAuthenticationRequiredCallback func(conn *Conn) error
  AuthUsernamePasswordCallback         func(conn *Conn, username, password []byte) error
  connectHandlers                      []ConnectHandler
  closeHandlers                        []CloseHandler
  counts                               [2]int
  AddressStore *AddressStore
}

type Conn struct {
  server *Server
  rwc    net.Conn
  User   string
  Password string
  Data   interface{}
}

type AddressStore struct {
  mapping map[string]*net.TCPAddr
}

// return the address which is mapped by the combination of username and password
// return might be nil, if the address was not saved yet
func (addrSt *AddressStore) getIPAddr(username, password string) *net.TCPAddr  {
  // the mapped string is just the concatenation of username and password
  return addrSt.mapping[username + password]
}

func New() *Server {
  counts := [2]int{0, 0}
  addrStore := &AddressStore{}
  addrStore.mapping = make(map[string]*net.TCPAddr)
  return &Server{
    Logger: log.New(os.Stderr, "", log.LstdFlags),
    counts: counts,
    AddressStore: addrStore,
  }
}

func (srv *Server) HandleConnect(h ConnectHandler) {
  srv.connectHandlers = append(srv.connectHandlers, h)
}

func (srv *Server) HandleConnectFunc(h func(c *Conn, host string) (newHost string, err error)) {
  srv.connectHandlers = append(srv.connectHandlers, FuncConnectHandler(h))
}

func (srv *Server) HandleClose(h CloseHandler) {
  srv.closeHandlers = append(srv.closeHandlers, h)
}

func (srv *Server) HandleCloseFunc(h func(c *Conn)) {
  srv.closeHandlers = append(srv.closeHandlers, FuncCloseHandler(h))
}

func (srv *Server) ListenAndServe(addr string) error {
  l, err := net.Listen("tcp", addr)
  if err != nil {
    return err
  }

  defer l.Close()
  var tempDelay time.Duration // how long to sleep on accept failure
  for {
    rw, err := l.Accept()
    if err != nil {
      if ne, ok := err.(net.Error); ok && ne.Temporary() {
        if tempDelay == 0 {
          tempDelay = 5 * time.Millisecond
        } else {
          tempDelay *= 2
        }
        if max := 1 * time.Second; tempDelay > max {
          tempDelay = max
        }
        srv.Logger.Printf("socks5: Accept error: %v; retrying in %v", err, tempDelay)
        time.Sleep(tempDelay)
        continue
      }
      return err
    }
    tempDelay = 0
    c, err := srv.newConn(rw)
    if err != nil {
      srv.Logger.Printf("socks5: Server.newConn: %v", err)
      continue
    }
    go c.serve()
  }
}

func (srv *Server) newConn(c net.Conn) (*Conn, error) {
  conn := &Conn{
    server: srv,
    rwc:    c,
  }
  return conn, nil
}

func (c *Conn) RemoteAddr() string {
  return c.rwc.RemoteAddr().String()
}

func (c *Conn) LocalAddr() string {
  return c.rwc.LocalAddr().String()
}

func (c *Conn) handshakeNoAuth() error {
  if err := c.server.AuthNoAuthenticationRequiredCallback(c); err != nil {
    return err
  }

  _, err := c.rwc.Write([]byte{verSocks5, authNoAuthenticationRequired})
  return err
}

func (c *Conn) handshakeUsernamePassword() error {
  if _, err := c.rwc.Write([]byte{verSocks5, authUsernamePassword}); err != nil {
    return err
  }

  var up userpass
  if _, err := up.ReadFrom(c.rwc); err != nil {
    c.rwc.Write([]byte{authUsernamePasswordVersion, authUsernamePasswordStatusFailure})
    return err
  }

  err := c.server.AuthUsernamePasswordCallback(c, up.uname, up.passwd)
  if err != nil {
    c.rwc.Write([]byte{authUsernamePasswordVersion, authUsernamePasswordStatusFailure})
    return err
  }

  _, err = c.rwc.Write([]byte{authUsernamePasswordVersion, authUsernamePasswordStatusSuccess})
  return err
}

func (c *Conn) handshake() error {
  var head header
  if _, err := head.ReadFrom(c.rwc); err != nil {
    return err
  }

  if c.server.AuthNoAuthenticationRequiredCallback != nil && bytes.IndexByte(head.methods, authNoAuthenticationRequired) != -1 {
    err := c.handshakeNoAuth()
    if err != ErrAuthenticationFailed {
      return err // success or critical error
    }
  }

  if c.server.AuthUsernamePasswordCallback != nil && bytes.IndexByte(head.methods, authUsernamePassword) != -1 {
    return c.handshakeUsernamePassword()
  }

  c.rwc.Write([]byte{verSocks5, authNoAcceptableMethods})
  return ErrAuthenticationFailed
}

func writeCommandErrorReply(c net.Conn, rep byte) error {
  _, err := c.Write([]byte{
    verSocks5,
    rep,
    rsvReserved,
    atypIPv4Address,
    0, 0, 0, 0,
    0, 0,
  })
  return err
}

// retrieve address for the credential combination of the connection
// if the credentials are used the first time, a new address is generated
func getFromAddr(connection *Conn) (*net.TCPAddr, error) {
  var err error
  addressStore := connection.server.AddressStore

  // try to get a stored IPAddr basaed on user and password
  address := addressStore.getIPAddr(connection.User, connection.Password)
  log.Printf("User: %v, PW: %v", connection.User, connection.Password)
  log.Printf("old addr: %v", address)

  // if no address was found, build a new one and store it
  if address == nil {
    // build random address
    address, err = buildNewRandomAddr()
    // if address is nil, there must be an error, which is returned later
    if address != nil {
      addressStore.mapping[connection.User + connection.Password] = address
      log.Printf("new addr: %v", address)
    }
  }
  log.Printf("E: %v", address)
  return address, err
}

// generate a random IPv6 address
// TODO RFC3041 conformity
// https://tools.ietf.org/html/rfc3041
func buildNewRandomAddr() (*net.TCPAddr, error) {
  // parse prefix to byte representation
  prefixIP, _, err := net.ParseCIDR("2001:470:1f0b:1354::/64")
  if err != nil {
    return nil, err
    log.Printf("ERR: %v", err)
  }

  // generate a 64bit random int and split it into a byte array
  randomByteArray := make([]byte, 8)
  binary.LittleEndian.PutUint64(randomByteArray, rand.Uint64())

  // addrArray is put together from two byte arrays of bits each
  // 1: `prefixIP[:8]` the first 8bits (0-7) of the prefix
  // 2: `randomByteArray...` each Element of randomByteArray
  addrArray := append(prefixIP[:8], randomByteArray...)
  // ipAddr is the 'IP' object instance for containing the addrArray
  ipAddr := make(net.IP, net.IPv6len)
  copy(ipAddr, addrArray)

  // TODO remove debugging code
  // q := net.ParseIP("2001:470:1f0b:1354:0:52:fdfc:721")
  // from := net.TCPAddr{q, 0, ""}

  // let the OS assign some port
  from := net.TCPAddr{ipAddr, 0, ""}
  return &from, nil
}

// handles the CONNECT command of the SOCKS5 proxy protocol
func (c *Conn) commandConnect(cmd *cmd) error {
  var err error

  // save the  destination address received fromAddress the client
  to := cmd.DestAddress()

  // execute handlers defined outside this library
  for _, h := range c.server.connectHandlers {
    to, err = h.HandleConnect(c, to)
    if err != nil {

      // If a handler returns an error, send ERROR answer to client
      if err == ErrConnectionNotAllowedByRuleset {
        writeCommandErrorReply(c.rwc, repConnectionNotAllowedByRuleset)
        return nil
      } else {
        writeCommandErrorReply(c.rwc, repGeneralSocksServerFailure)
        return err
      }
    }
  }

  var conn net.Conn

  log.Printf("D: %v", to)

  // check if the target address is reachable over IPv6
  // if it isn't, let the operating system decide how to connect
  // if it is, resolve to an IPv6 address and connect to that
  ipv6_host, no_ipv6_error := net.ResolveTCPAddr("tcp6", to)
  if no_ipv6_error != nil {
    log.Printf("C: %v", no_ipv6_error)
    conn, err = net.Dial("tcp", to)
  } else {
    // Get the address that will be used as the from address for the outbound
    // connection.
    fromAddress, fromAddressError := getFromAddr(c)
    if fromAddressError != nil {
      writeCommandErrorReply(c.rwc, repGeneralSocksServerFailure)
      return err
    } else {
      log.Printf("From Adress: %v", fromAddress)
    }

    log.Printf("To Adress: %v", ipv6_host)
    dialer := net.Dialer{LocalAddr: fromAddress}
    conn, err = dialer.Dial("tcp6", ipv6_host.String())
  }

  // context-aware behaviour ends here
  // from now on normal SOCKS5 process

  if err != nil {
    switch e := err.(type) {
    case *net.OpError:
      switch e.Err.(type) {
      case *net.DNSError:
        writeCommandErrorReply(c.rwc, repHostUnreachable)
        return err
      }
      writeCommandErrorReply(c.rwc, repGeneralSocksServerFailure)
      return err

    default:
      writeCommandErrorReply(c.rwc, repGeneralSocksServerFailure)
      return err
    }
  }

  defer conn.Close()

  r := &cmdResp{
    ver: verSocks5,
    rep: repSucceeded,
    rsv: rsvReserved,
  }

  host, port, err := net.SplitHostPort(conn.LocalAddr().String())
  if err != nil {
    writeCommandErrorReply(c.rwc, repGeneralSocksServerFailure)
    return err
  }

  ip := net.ParseIP(host)
  if ipv4 := ip.To4(); ipv4 != nil {
    r.atyp = atypIPv4Address
    r.bnd_addr = ipv4[:net.IPv4len]
  } else {
    r.atyp = atypIPv6Address
    r.bnd_addr = ip[:net.IPv6len]
  }

  prt, err := strconv.Atoi(port)
  if err != nil {
    writeCommandErrorReply(c.rwc, repGeneralSocksServerFailure)
    return err
  }
  r.bnd_port = uint16(prt)

  if _, err = r.WriteTo(c.rwc); err != nil {
    writeCommandErrorReply(c.rwc, repGeneralSocksServerFailure)
    return err
  }

  var wg sync.WaitGroup
  var err2 error
  wg.Add(2)
  go func() {
    defer wg.Done()
    _, err = io.Copy(c.rwc, conn)
  }()
  go func() {
    defer wg.Done()
    _, err2 = io.Copy(conn, c.rwc)
  }()
  wg.Wait()

  if err != nil && err2 != nil {
    return errors.New("socks5: " + err.Error() + " / " + err2.Error())
  }
  if err != nil {
    prt, err := strconv.Atoi(port)
    if err != nil {
      writeCommandErrorReply(c.rwc, repGeneralSocksServerFailure)
      return err
    }
    r.bnd_port = uint16(prt)

    return err
  }
  if err2 != nil {
    return err2
  }
  return nil
}

func (c *Conn) command() error {
  var cmd cmd
  if _, err := cmd.ReadFrom(c.rwc); err != nil {
    if err == ErrAddressTypeNotSupported {
      writeCommandErrorReply(c.rwc, repAddressTypeNotSupported)
    }
    return err
  }

  switch cmd.cmd {
  case cmdConnect:
    return c.commandConnect(&cmd)
  default:
    return writeCommandErrorReply(c.rwc, repComandNotSupported)
  }
}

func (c *Conn) serve() {
  defer func() {
    if err := recover(); err != nil {
      const size = 4096
      buf := make([]byte, size)
      buf = buf[:runtime.Stack(buf, false)]
      c.server.Logger.Printf("socks5: panic serving %v: %v\n%s", c.rwc.RemoteAddr(), err, buf)
    }
    c.close()
  }()

  if err := c.handshake(); err != nil {
    c.server.Logger.Printf("socks5: Conn.serve: Handshake failed: %v", err)
    return
  }

  if err := c.command(); err != nil {
    c.server.Logger.Printf("socks5: Conn.serve: command execution failed: %v", err)
    return
  }
}

func (c *Conn) close() {
  for _, h := range c.server.closeHandlers {
    h.HandleClose(c)
  }

  if c.rwc != nil {
    c.rwc.Close()
    c.rwc = nil
  }
}
