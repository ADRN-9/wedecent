package portforward

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/mesh"
)

type memoryAudit struct {
	mu sync.Mutex
	events []audit.Event
	failType, failOutcome string
}
func (a *memoryAudit) Append(event audit.Event) error {
	a.mu.Lock(); defer a.mu.Unlock()
	if event.Type == a.failType && (a.failOutcome == "" || event.Outcome == a.failOutcome) { return errors.New("audit persistence unavailable") }
	a.events = append(a.events, event); return nil
}
func (a *memoryAudit) count() int { a.mu.Lock(); defer a.mu.Unlock(); return len(a.events) }

type queueListener struct {
	addr net.Addr
	incoming chan net.Conn
	closed chan struct{}
	once sync.Once
}
func newQueueListener() *queueListener {
	return &queueListener{addr:&net.TCPAddr{IP:net.ParseIP("127.0.0.1"),Port:43123},incoming:make(chan net.Conn,16),closed:make(chan struct{})}
}
func newQueueListenerAddress(ip string) *queueListener {
	listener := newQueueListener()
	listener.addr = &net.TCPAddr{IP: net.ParseIP(ip), Port: 43123}
	return listener
}
func (l *queueListener) Accept() (net.Conn,error) {
	select { case conn:=<-l.incoming: return conn,nil; case <-l.closed: return nil,net.ErrClosed }
}
func (l *queueListener) Close() error { l.once.Do(func(){close(l.closed)}); return nil }
func (l *queueListener) Addr() net.Addr { return l.addr }
func (l *queueListener) inject(conn net.Conn) bool {
	select { case l.incoming<-conn: return true; case <-l.closed: return false }
}

type pipeConnector struct {
	mu sync.Mutex
	calls int
	opened chan net.Conn
	block <-chan struct{}
}
func (c *pipeConnector) Open(ctx context.Context, _ Claims) (net.Conn,error) {
	c.mu.Lock(); c.calls++; c.mu.Unlock()
	left,right:=net.Pipe()
	if c.opened!=nil { select { case c.opened<-right: default: } }
	if c.block!=nil {
		select { case <-c.block: case <-ctx.Done(): _=left.Close(); _=right.Close(); return nil,ctx.Err() }
	}
	return left,nil
}
func (c *pipeConnector) callCount() int { c.mu.Lock(); defer c.mu.Unlock(); return c.calls }

type allowListenerAdmin struct { calls int; err error }
func (a *allowListenerAdmin) AuthorizePortForwardListener(context.Context, Claims) error { a.calls++; return a.err }

func testManagerLimits() ManagerLimits {
	return ManagerLimits{MaxForwards:8,MaxForwardsPerDevice:4,MaxConnections:8,MaxConnectionsPerDevice:4,MaxConnectionsPerForward:4,MaxDuration:3*time.Minute,IdleTimeout:30*time.Second,DialTimeout:time.Second}
}

func makeTestManager(t *testing.T, local mesh.DeviceID, claims Claims, connector Connector, log *memoryAudit, admin ListenerAuthorizer, listen func(string,string)(net.Listener,error)) (*Manager,Authorization,*queueListener) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader); if err!=nil { t.Fatal(err) }
	auth, err := SignAuthorization(privateKey, claims); if err!=nil { t.Fatal(err) }
	now:=time.Now().UTC().Truncate(time.Millisecond)
	replay:=NewMemoryReplay(32); replay.Now=func() time.Time { return now }
	verifier:=AuthorizationVerifier{PublicKey:publicKey,Replay:replay,Now:func() time.Time { return now }}
	listener:=newQueueListener()
	if listen==nil {
		listen=func(network,address string)(net.Listener,error) {
			if network!="tcp" || address!="127.0.0.1:43123" { t.Errorf("unexpected listener bind %s %s",network,address) }
			return listener,nil
		}
	}
	if log==nil { log=&memoryAudit{} }
	manager,err:=NewManager(ManagerConfig{
		LocalDeviceID:local,Verifier:verifier,Connector:connector,ListenerAuthorizer:admin,
		Audit:log,Limits:testManagerLimits(),Listen:listen,
	})
	if err!=nil { t.Fatal(err) }
	return manager,auth,listener
}

func TestManagerLocalForwardBridgesAndStopsChild(t *testing.T) {
	claims:=testClaims(time.Now().UTC().Truncate(time.Millisecond),DirectionLocal)
	connector:=&pipeConnector{opened:make(chan net.Conn,1)}
	log:=&memoryAudit{}
	manager,auth,listener:=makeTestManager(t,testInitiator,claims,connector,log,nil,nil)
	info,err:=manager.Start(context.Background(),auth); if err!=nil { t.Fatal(err) }
	if info.ListenerAddress!="127.0.0.1:43123" { t.Fatalf("listener = %q",info.ListenerAddress) }
	client,core:=net.Pipe(); if !listener.inject(core) { t.Fatal("listener closed") }
	var remote net.Conn
	select { case remote=<-connector.opened: case <-time.After(time.Second): t.Fatal("connector not called") }
	defer remote.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	if _,err:=client.Write([]byte("request")); err!=nil { t.Fatal(err) }
	buf:=make([]byte,7); if _,err:=io.ReadFull(remote,buf); err!=nil { t.Fatal(err) }
	if string(buf)!="request" { t.Fatalf("forwarded %q",buf) }
	if _,err:=remote.Write([]byte("reply")); err!=nil { t.Fatal(err) }
	reply:=make([]byte,5); if _,err:=io.ReadFull(client,reply); err!=nil { t.Fatal(err) }
	if string(reply)!="reply" { t.Fatalf("reply %q",reply) }
	if err:=manager.Stop(context.Background(),claims.ForwardingID); err!=nil { t.Fatal(err) }
	if len(manager.List())!=0 { t.Fatal("forward still active") }
	if _,err:=client.Read(make([]byte,1)); err==nil { t.Fatal("child survived Stop") }
	_ = client.Close()
	if log.count()<4 { t.Fatalf("missing lifecycle audit events: %d",log.count()) }
}

func TestManagerRemoteForwardMustRunOnDestinationDevice(t *testing.T) {
	claims:=testClaims(time.Now().UTC().Truncate(time.Millisecond),DirectionRemote)
	claims.Permission=PermissionRemote
	wrong,auth,_:=makeTestManager(t,testInitiator,claims,&pipeConnector{},nil,nil,nil)
	if _,err:=wrong.Start(context.Background(),auth); !errors.Is(err,ErrWrongListenerDevice) { t.Fatalf("wrong endpoint: %v",err) }
	right,auth2,listener:=makeTestManager(t,testDestination,claims,&pipeConnector{},nil,nil,nil)
	if _,err:=right.Start(context.Background(),auth2); err!=nil { t.Fatal(err) }
	if err:=right.Stop(context.Background(),claims.ForwardingID); err!=nil { t.Fatal(err) }
	if _,err:=listener.Accept(); !errors.Is(err,net.ErrClosed) { t.Fatalf("listener not closed: %v",err) }
}

func TestManagerPublicListenerRequiresRouterAdmin(t *testing.T) {
	claims:=testClaims(time.Now().UTC().Truncate(time.Millisecond),DirectionLocal)
	claims.Listener=ListenerPolicy{Address:"1.1.1.1",Port:43123,Exposure:ExposurePublic}
	denied,auth,_:=makeTestManager(t,testInitiator,claims,&pipeConnector{},nil,nil,func(string,string)(net.Listener,error){return newQueueListener(),nil})
	if _,err:=denied.Start(context.Background(),auth); !errors.Is(err,ErrListenerAdminRequired) { t.Fatalf("public bind error = %v",err) }
	admin:=&allowListenerAdmin{}
	allowed,auth2,_:=makeTestManager(t,testInitiator,claims,&pipeConnector{},nil,admin,func(string,string)(net.Listener,error){return newQueueListenerAddress("1.1.1.1"),nil})
	if _,err:=allowed.Start(context.Background(),auth2); err!=nil { t.Fatal(err) }
	if admin.calls!=1 { t.Fatalf("admin checks = %d",admin.calls) }
	if err:=allowed.Close(); err!=nil { t.Fatal(err) }
}

func TestManagerAuditFailuresFailClosed(t *testing.T) {
	claims:=testClaims(time.Now().UTC().Truncate(time.Millisecond),DirectionLocal)
	log:=&memoryAudit{failType:"port_forward.start",failOutcome:"attempt"}
	calls:=0
	manager,auth,_:=makeTestManager(t,testInitiator,claims,&pipeConnector{},log,nil,func(string,string)(net.Listener,error){calls++;return newQueueListener(),nil})
	if _,err:=manager.Start(context.Background(),auth); err==nil { t.Fatal("start passed failed audit write") }
	if calls!=0 { t.Fatalf("listener opened %d times",calls) }

	log2:=&memoryAudit{failType:"port_forward.started",failOutcome:"success"}
	listener:=newQueueListener()
	manager2,auth2,_:=makeTestManager(t,testInitiator,claims,&pipeConnector{},log2,nil,func(string,string)(net.Listener,error){return listener,nil})
	if _,err:=manager2.Start(context.Background(),auth2); err==nil { t.Fatal("start passed missing durable success audit") }
	select { case <-listener.closed: case <-time.After(time.Second): t.Fatal("listener leaked after audit failure") }
}

func TestManagerLimitsAndDeviceRevocationCloseChildren(t *testing.T) {
	claims:=testClaims(time.Now().UTC().Truncate(time.Millisecond),DirectionLocal)
	claims.Limits.MaxConnections=1
	block:=make(chan struct{})
	connector:=&pipeConnector{opened:make(chan net.Conn,2),block:block}
	manager,auth,listener:=makeTestManager(t,testInitiator,claims,connector,nil,nil,nil)
	if _,err:=manager.Start(context.Background(),auth); err!=nil { t.Fatal(err) }
	client,core:=net.Pipe(); listener.inject(core)
	select { case <-connector.opened: case <-time.After(time.Second): t.Fatal("first child not opened") }
	secondClient,secondCore:=net.Pipe(); listener.inject(secondCore)
	_ = secondClient.SetReadDeadline(time.Now().Add(time.Second))
	if _,err:=secondClient.Read(make([]byte,1)); err==nil { t.Fatal("over-limit child remained open") }
	if connector.callCount()!=1 { t.Fatalf("connector calls = %d",connector.callCount()) }
	if count,err:=manager.RevokeDevice(context.Background(),testDestination); err!=nil || count!=1 { t.Fatalf("revoke count=%d err=%v",count,err) }
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _,err:=client.Read(make([]byte,1)); err==nil { t.Fatal("revoked child remained open") }
	_ = client.Close(); _ = secondClient.Close()
}

func TestManagerExpiryClosesListener(t *testing.T) {
	now:=time.Now().UTC().Truncate(time.Millisecond)
	claims:=testClaims(now,DirectionLocal)
	claims.ExpiresAtUnixMS=now.Add(150*time.Millisecond).UnixMilli()
	claims.Route.ExpiresAt=time.UnixMilli(claims.ExpiresAtUnixMS).UTC()
	listener:=newQueueListener()
	manager,auth,_:=makeTestManager(t,testInitiator,claims,&pipeConnector{},nil,nil,func(string,string)(net.Listener,error){return listener,nil})
	if _,err:=manager.Start(context.Background(),auth); err!=nil { t.Fatal(err) }
	select { case <-listener.closed: case <-time.After(2*time.Second): t.Fatal("listener survived capability expiry") }
	deadline:=time.After(time.Second)
	for len(manager.List())!=0 {
		select { case <-deadline: t.Fatal("expired forward remains registered"); case <-time.After(5*time.Millisecond): }
	}
}
