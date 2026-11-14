// Package fridarpc implements the subset of Frida 17's peer protocol used by
// capture and signing. It uses WebSocket + D-Bus, with no host Frida runtime.
// Wire definitions: frida-core 17.26.2 lib/base/{session,socket,rpc}.vala.
package fridarpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/net/websocket"
)

const hostPath = "/re/frida/HostSession"
const hostInterface = "re.frida.HostSession17"
const agentInterface = "re.frida.AgentSession17"

type sessionID struct{ Handle string }
type scriptID struct{ Handle uint32 }
type process struct {
	PID        uint32
	Name       string
	Parameters map[string]dbus.Variant
}
type wireMessage struct {
	Kind    int32
	Script  scriptID
	Text    string
	HasData bool
	Data    []byte
}

// Event contains an agent's send() payload and optional binary attachment.
type Event struct {
	Payload json.RawMessage
	Data    []byte
}
type rpcResult struct {
	value json.RawMessage
	data  []byte
	err   error
}

type peer struct {
	ws        *websocket.Conn
	raw       net.Conn
	closing   atomic.Bool
	writeMu   sync.Mutex
	mu        sync.Mutex
	pending   map[uint32]chan *dbus.Message
	rpcs      map[string]chan rpcResult
	serial    atomic.Uint32
	rpcSerial atomic.Uint64
	done      chan struct{}
	once      sync.Once
	err       error
	event     func(Event)
	sink      dbus.ObjectPath
}

// Script owns one attached session and its transport.
type Script struct {
	peer     *peer
	path     string
	id       scriptID
	PID      uint32
	once     sync.Once
	closeErr error
}

func Attach(ctx context.Context, remote, name, source string, event func(Event)) (*Script, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", remote)
	if err != nil {
		return nil, err
	}

	return AttachConn(ctx, conn, remote, name, source, event)
}

// AttachConn takes ownership of conn, including on error. It also supports SSH
// forwarding, keeping the device server bound to loopback during capture.
func AttachConn(ctx context.Context, conn net.Conn, host, name, source string, event func(Event)) (*Script, error) {
	handshakeCtx, stopHandshake := context.WithTimeout(ctx, 20*time.Second)
	defer stopHandshake()

	abortHandshake := context.AfterFunc(handshakeCtx, func() { _ = conn.Close() })
	defer abortHandshake()

	deadline := time.Now().Add(20 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	_ = conn.SetDeadline(deadline)

	cfg, err := websocket.NewConfig("ws://"+host+"/ws", "http://"+host)
	if err != nil {
		conn.Close()
		return nil, err
	}

	ws, err := websocket.NewClient(cfg, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	abortHandshake()

	_ = conn.SetDeadline(time.Time{})
	ws.PayloadType = websocket.BinaryFrame
	ws.MaxPayloadBytes = 256 << 10

	p := &peer{ws: ws, raw: conn, pending: map[uint32]chan *dbus.Message{}, rpcs: map[string]chan rpcResult{}, done: make(chan struct{}), event: event}
	go p.readLoop()

	failed := true
	defer func() {
		if failed {
			p.close(errors.New("attach through Frida failed"))
		}
	}()

	var pid uint32

	findCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	for pid == 0 {
		var processes []process

		body, err := p.call(findCtx, hostPath, hostInterface, "EnumerateProcesses", map[string]dbus.Variant{})
		if err != nil {
			return nil, err
		}

		if err = dbus.Store(body, &processes); err != nil {
			return nil, err
		}

		for _, item := range processes {
			if item.Name == name {
				if pid != 0 {
					return nil, errors.New("ambiguous Frida process name")
				}

				pid = item.PID
			}
		}

		if pid == 0 {
			select {
			case <-findCtx.Done():
				return nil, fmt.Errorf("find %s: %w", name, findCtx.Err())
			case <-time.After(250 * time.Millisecond):
			}
		}
	}

	body, err := p.call(ctx, hostPath, hostInterface, "Attach", pid, map[string]dbus.Variant{})
	if err != nil {
		return nil, fmt.Errorf("attach %s: %w", name, err)
	}

	var session sessionID
	if err = dbus.Store(body, &session); err != nil {
		return nil, err
	}

	s := &Script{peer: p, path: "/re/frida/AgentSession/" + session.Handle, PID: pid}
	p.mu.Lock()
	p.sink = dbus.ObjectPath("/re/frida/AgentMessageSink/" + session.Handle)
	p.mu.Unlock()

	defer func() {
		if failed {
			_ = s.Close()
		}
	}()

	body, err = p.call(ctx, s.path, agentInterface, "CreateScript", source, map[string]dbus.Variant{})
	if err != nil {
		return nil, err
	}

	if err = dbus.Store(body, &s.id); err != nil {
		return nil, err
	}

	if _, err = p.call(ctx, s.path, agentInterface, "LoadScript", s.id); err != nil {
		return nil, err
	}

	failed = false

	return s, nil
}

func (p *peer) close(err error) {
	p.once.Do(func() {
		p.mu.Lock()
		p.err = err
		p.mu.Unlock()
		close(p.done)
		_ = p.raw.Close()
		_ = p.ws.Close()
	})
}
func (p *peer) failure() error { p.mu.Lock(); defer p.mu.Unlock(); return p.err }

func (p *peer) write(ctx context.Context, m *dbus.Message, serial uint32) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	if err := ctx.Err(); err != nil {
		return err
	}

	if m.Headers == nil {
		m.Headers = map[dbus.HeaderField]dbus.Variant{}
	}

	if len(m.Body) > 0 {
		m.Headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf(m.Body...))
	}

	var b bytes.Buffer
	if err := m.EncodeTo(&b, binary.LittleEndian); err != nil {
		return err
	}
	// The codec exposes decoded serials but has no setter. Serial is the fixed
	// uint32 field at offset 8 in the standard D-Bus wire header.
	data := b.Bytes()
	binary.LittleEndian.PutUint32(data[8:12], serial)
	// SSH forwards do not implement deadlines. Close the transport on timeout,
	// including when another writer holds the lock.
	abort := context.AfterFunc(ctx, func() { p.close(ctx.Err()) })
	defer abort()

	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	deadline := time.Now().Add(20 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	_ = p.ws.SetWriteDeadline(deadline)
	defer p.ws.SetWriteDeadline(time.Time{})

	for len(data) > 0 {
		n := min(len(data), 256<<10)
		if _, err := p.ws.Write(data[:n]); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			return err
		}

		data = data[n:]
	}

	return nil
}

func (p *peer) call(ctx context.Context, path, iface, method string, args ...any) ([]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	id := p.serial.Add(1)
	ch := make(chan *dbus.Message, 1)

	p.mu.Lock()
	p.pending[id] = ch

	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.pending, id); p.mu.Unlock() }()

	m := &dbus.Message{Type: dbus.TypeMethodCall, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldPath: dbus.MakeVariant(dbus.ObjectPath(path)), dbus.FieldInterface: dbus.MakeVariant(iface), dbus.FieldMember: dbus.MakeVariant(method)}, Body: args}
	if err := p.write(ctx, m, id); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		return nil, p.failure()
	case reply := <-ch:
		if reply.Type == dbus.TypeError {
			return nil, fmt.Errorf("request %s rejected by Frida (%v)", method, reply.Headers[dbus.FieldErrorName].Value())
		}

		return reply.Body, nil
	}
}

func readMessage(r io.Reader) (*dbus.Message, error) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	var order binary.ByteOrder = binary.LittleEndian
	if header[0] == 'B' {
		order = binary.BigEndian
	} else if header[0] != 'l' {
		return nil, errors.New("invalid D-Bus byte order")
	}

	n := uint64(order.Uint32(header[12:16]))
	n = (n + 7) &^ 7

	n += uint64(order.Uint32(header[4:8]))
	if n > 64<<20 {
		return nil, errors.New("the Frida message exceeds size limit")
	}

	packet := make([]byte, 16+int(n))
	copy(packet, header)

	if _, err := io.ReadFull(r, packet[16:]); err != nil {
		return nil, err
	}

	return dbus.DecodeMessage(bytes.NewReader(packet))
}

func (p *peer) readLoop() {
	for {
		m, err := readMessage(p.ws)
		if err != nil {
			p.close(err)
			return
		}

		if m.Type == dbus.TypeMethodReply || m.Type == dbus.TypeError {
			id, _ := m.Headers[dbus.FieldReplySerial].Value().(uint32)

			p.mu.Lock()
			ch := p.pending[id]
			p.mu.Unlock()

			if ch != nil {
				select {
				case ch <- m:
				default:
				}
			}
		} else if m.Type == dbus.TypeMethodCall {
			p.mu.Lock()
			sink := p.sink
			p.mu.Unlock()

			if m.Headers[dbus.FieldPath].Value() != sink || m.Headers[dbus.FieldInterface].Value() != "re.frida.AgentMessageSink17" || m.Headers[dbus.FieldMember].Value() != "PostMessages" {
				p.close(errors.New("unexpected Frida callback"))
				return
			}

			var (
				messages []wireMessage
				batch    uint32
			)
			if err = dbus.Store(m.Body, &messages, &batch); err != nil {
				p.close(err)
				return
			}

			for _, message := range messages {
				if message.Kind == 1 {
					p.deliver(message)
				}
			}

			if m.Flags&dbus.FlagNoReplyExpected == 0 {
				reply := &dbus.Message{Type: dbus.TypeMethodReply, Headers: map[dbus.HeaderField]dbus.Variant{dbus.FieldReplySerial: dbus.MakeVariant(m.Serial())}}
				if err = p.write(context.Background(), reply, p.serial.Add(1)); err != nil {
					p.close(err)
					return
				}
			}
		} else if m.Type == dbus.TypeSignal && m.Headers[dbus.FieldMember].Value() == "AgentSessionDetached" && !p.closing.Load() {
			p.close(errors.New("the Frida session detached"))
			return
		}
	}
}

func (p *peer) deliver(m wireMessage) {
	var envelope struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal([]byte(m.Text), &envelope); err != nil {
		p.close(errors.New("invalid Frida message"))
		return
	}

	if envelope.Type == "error" {
		p.close(errors.New("the Frida agent reported an exception"))
		return
	}

	if envelope.Type != "send" {
		return
	}

	var fields []json.RawMessage
	if json.Unmarshal(envelope.Payload, &fields) == nil && len(fields) >= 4 && string(fields[0]) == `"frida:rpc"` {
		var id, status string

		_ = json.Unmarshal(fields[1], &id)
		_ = json.Unmarshal(fields[2], &status)

		result := rpcResult{value: fields[3]}
		if m.HasData {
			result.data = m.Data
		}

		if status != "ok" {
			result.err = errors.New("the Frida RPC returned an exception")
		}

		p.mu.Lock()
		ch := p.rpcs[id]
		p.mu.Unlock()

		if ch != nil {
			select {
			case ch <- result:
			default:
			}
		}

		return
	}

	if p.event != nil {
		p.event(Event{Payload: envelope.Payload, Data: m.Data})
	}
}

// Call returns a JSON result or an ArrayBuffer attachment. Cancellation is
// enforced by the host even when an agent is blocked or detached.
func (s *Script) Call(ctx context.Context, method string, args ...any) (json.RawMessage, []byte, error) {
	id := strconv.FormatUint(s.peer.rpcSerial.Add(1), 10)
	ch := make(chan rpcResult, 1)

	s.peer.mu.Lock()
	s.peer.rpcs[id] = ch

	s.peer.mu.Unlock()
	defer func() { s.peer.mu.Lock(); delete(s.peer.rpcs, id); s.peer.mu.Unlock() }()

	if args == nil {
		args = []any{}
	}

	request, err := json.Marshal([]any{"frida:rpc", id, "call", method, args})
	if err != nil {
		return nil, nil, err
	}

	_, err = s.peer.call(ctx, s.path, agentInterface, "PostMessages", []wireMessage{{Kind: 1, Script: s.id, Text: string(request), Data: []byte{}}}, uint32(0))
	if err != nil {
		return nil, nil, err
	}

	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-s.peer.done:
		return nil, nil, s.peer.failure()
	case r := <-ch:
		return r.value, r.data, r.err
	}
}

func (s *Script) Close() error {
	s.once.Do(func() {
		s.peer.closing.Store(true)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		_, s.closeErr = s.peer.call(ctx, s.path, agentInterface, "Close")
		s.peer.close(errors.New("the Frida session closed"))
	})

	return s.closeErr
}
