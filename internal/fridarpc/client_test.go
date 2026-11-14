package fridarpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/net/websocket"
)

func fakeServer(t *testing.T, failLoad bool) string {
	t.Helper()

	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()

		ws.PayloadType = websocket.BinaryFrame
		serial := uint32(10)

		send := func(m *dbus.Message) error {
			if len(m.Body) > 0 {
				m.Headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf(m.Body...))
			}

			var b bytes.Buffer
			if err := m.EncodeTo(&b, binary.LittleEndian); err != nil {
				return err
			}

			serial++
			data := b.Bytes()
			binary.LittleEndian.PutUint32(data[8:12], serial)

			for len(data) > 0 {
				n := min(len(data), 256<<10)
				if _, err := ws.Write(data[:n]); err != nil {
					return err
				}

				data = data[n:]
			}

			return nil
		}
		for {
			m, err := readMessage(ws)
			if err != nil {
				return
			}

			if m.Type != dbus.TypeMethodCall {
				continue
			}

			method, _ := m.Headers[dbus.FieldMember].Value().(string)
			reply := &dbus.Message{Type: dbus.TypeMethodReply, Headers: map[dbus.HeaderField]dbus.Variant{dbus.FieldReplySerial: dbus.MakeVariant(m.Serial())}}

			var request []json.RawMessage

			switch method {
			case "EnumerateProcesses":
				reply.Body = []any{[]process{{PID: 7, Name: "adid", Parameters: map[string]dbus.Variant{}}}}
			case "Attach":
				reply.Body = []any{sessionID{"abc"}}
			case "CreateScript":
				reply.Body = []any{scriptID{1}}
			case "LoadScript":
				if failLoad {
					reply.Type = dbus.TypeError
					reply.Headers[dbus.FieldErrorName] = dbus.MakeVariant("re.frida.Error.InvalidArgument")
				}
			case "PostMessages":
				signature := m.Headers[dbus.FieldSignature].Value().(dbus.Signature).String()
				if signature != "a(i(u)sbay)u" {
					t.Errorf("wrong Frida message signature: %s", signature)
					return
				}

				var (
					messages []wireMessage
					batch    uint32
				)
				if err = dbus.Store(m.Body, &messages, &batch); err != nil || len(messages) != 1 {
					t.Errorf("invalid messages: %v", err)
					return
				}

				if err = json.Unmarshal([]byte(messages[0].Text), &request); err != nil {
					t.Error(err)
					return
				}
			case "Close":
			default:
				t.Errorf("unexpected method: %s", method)
				return
			}

			if err = send(reply); err != nil {
				return
			}

			if method == "Close" {
				return
			}

			if method != "PostMessages" {
				continue
			}

			var id, operation string
			json.Unmarshal(request[1], &id)
			json.Unmarshal(request[3], &operation)

			if operation == "stall" {
				continue
			}

			status := "ok"

			var (
				value any = map[string]any{"ready": true}
				data  []byte
			)
			if operation == "binary" {
				data = bytes.Repeat([]byte{0x37}, 300<<10)
				value = nil
			}

			if operation == "fail" {
				status = "error"
				value = "private device exception"
			}

			body, _ := json.Marshal(map[string]any{"type": "send", "payload": []any{"frida:rpc", id, status, value}})

			callback := &dbus.Message{Type: dbus.TypeMethodCall, Headers: map[dbus.HeaderField]dbus.Variant{
				dbus.FieldPath: dbus.MakeVariant(dbus.ObjectPath("/re/frida/AgentMessageSink/abc")), dbus.FieldInterface: dbus.MakeVariant("re.frida.AgentMessageSink17"), dbus.FieldMember: dbus.MakeVariant("PostMessages")}, Body: []any{[]wireMessage{{Kind: 1, Script: scriptID{1}, Text: string(body), HasData: data != nil, Data: data}}, uint32(0)}}
			if err = send(callback); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)

	return strings.TrimPrefix(srv.URL, "http://")
}

func TestPeerRPCBinaryAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	script, err := Attach(ctx, fakeServer(t, false), "adid", "source", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer script.Close()

	raw, data, err := script.Call(ctx, "json")
	if err != nil || string(raw) != `{"ready":true}` || data != nil {
		t.Fatalf("JSON reply %s %v", raw, err)
	}

	_, data, err = script.Call(ctx, "binary")
	if err != nil || !bytes.Equal(data, bytes.Repeat([]byte{0x37}, 300<<10)) {
		t.Fatal("binary RPC failed", err)
	}

	_, _, err = script.Call(ctx, "fail")
	if err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("device exception was not sanitized", err)
	}

	bounded, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	defer stop()

	_, _, err = script.Call(bounded, "stall")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unbounded RPC: %v", err)
	}

	if err = script.Close(); err != nil {
		t.Fatal(err)
	}

	if err = script.Close(); err != nil {
		t.Fatal("close must be idempotent", err)
	}
}
func TestLoadFailureClosesSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := Attach(ctx, fakeServer(t, true), "adid", "source", nil); err == nil {
		t.Fatal("load failure accepted")
	}
}
func TestRejectOversizedFrame(t *testing.T) {
	header := make([]byte, 16)
	header[0] = 'l'
	binary.LittleEndian.PutUint32(header[4:], 65<<20)

	if _, err := readMessage(bytes.NewReader(header)); err == nil {
		t.Fatal("unbounded message accepted")
	}
}

// SSH forwarded connections reject deadlines; cancellation must close the
// underlying transport to interrupt a stalled websocket write.
type stalledConn struct {
	net.Conn
	stall  atomic.Bool
	once   sync.Once
	closed chan struct{}
}

func (c *stalledConn) Write(b []byte) (int, error) {
	if c.stall.Load() {
		<-c.closed
		return 0, net.ErrClosed
	}

	return c.Conn.Write(b)
}
func (c *stalledConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
func (*stalledConn) SetDeadline(time.Time) error      { return errors.New("unsupported") }
func (*stalledConn) SetWriteDeadline(time.Time) error { return errors.New("unsupported") }

func TestWriteCancellationWithoutTransportDeadlines(t *testing.T) {
	remote := fakeServer(t, false)

	raw, err := net.Dial("tcp", remote)
	if err != nil {
		t.Fatal(err)
	}

	conn := &stalledConn{Conn: raw, closed: make(chan struct{})}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	script, err := AttachConn(ctx, conn, remote, "adid", "source", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer script.Close()

	conn.stall.Store(true)

	callCtx, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	defer stop()

	done := make(chan error, 1)

	go func() { _, _, err := script.Call(callCtx, "json"); done <- err }()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("write cancellation: %v", err)
		}
	case <-time.After(time.Second):
		conn.Close()
		t.Fatal("write remained blocked after cancellation")
	}
}
