//go:build !windows
// +build !windows

package bls

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"google.golang.org/grpc"
)

type Bls12381Sign interface {
	GenerateKeys() (secret []byte, public []byte)
	Sign(sk, pk, msg []byte) (signature []byte, err error)
	Verify(apk, sig, msg []byte) (err error)
	CreateApk(pk []byte) (apk []byte, err error)
	AggregatePk(apk []byte, pks ...[]byte)
	AggregateSig(sig []byte, sigs ...[]byte)
}

func SwitchToCgo() {
	ipc.disconnect()
	GenerateKeys = cgo.GenerateKeys
	Sign = cgo.Sign
	Verify = cgo.Verify
	CreateApk = cgo.CreateApk
	AggregatePk = cgo.AggregatePk
	AggregateSig = cgo.AggregateSig
}

func SwitchToIPC() {
	ipc.connect()
	GenerateKeys = ipc.GenerateKeys
	Sign = ipc.Sign
	Verify = ipc.Verify
	CreateApk = ipc.CreateApk
	AggregatePk = ipc.AggregatePk
	AggregateSig = ipc.AggregateSig
	time.Sleep(time.Second / 2)
}

type ipcState struct {
	connected bool
	cmd       *exec.Cmd
	SignerClient
	*grpc.ClientConn
}

const (
	ipcPath = "/tmp/bls12381svc.sock"
	//ipcPath       = "127.0.0.1:9476"
	ipcSvcBinPath = "/tmp/bls12381svc"
)

var ipc = new(ipcState)

func (s *ipcState) connect() {
	if s.connected {
		return
	}
	if _, err := os.Stat(ipcSvcBinPath); os.IsNotExist(err) {
		// write the IPC service binary to disk
		if err := ioutil.WriteFile(
			ipcSvcBinPath, Binary, 0o700,
		); err != nil {
			panic(err) // not sure what better to do just yet
		}
	}

	// spawn the IPC service
	s.cmd = exec.Command(ipcSvcBinPath)
	// command will print output to parent terminal
	s.cmd.Stdout = os.Stdout
	s.cmd.Stderr = os.Stderr
	if err := s.cmd.Start(); err != nil {
		panic(err)
	}

	time.Sleep(time.Second / 4)

	// connect the IPC
	dialer := func(ctx context.Context, path string) (net.Conn, error) {
		return net.Dial("unix", ipcPath)
	}

	var err error
	s.ClientConn, err = grpc.Dial(
		"unix://"+ipcPath,
		grpc.WithInsecure(),
		grpc.WithContextDialer(dialer),
	)
	if err != nil {
		panic(err)
	}

	s.SignerClient = NewSignerClient(s.ClientConn)
	s.ClientConn.Connect()
	s.connected = true
}

func eprintln(args ...interface{}) {
	_, _ = fmt.Fprint(os.Stderr, "cli: ")
	_, _ = fmt.Fprintln(os.Stderr, args...)
}

func (s *ipcState) disconnect() {
	if !s.connected {
		return
	}
	//  mark that we are not connected so nobody tries to use this
	s.connected = false

	// disconnect the IPC
	if err := s.ClientConn.Close(); err != nil {
		eprintln(err)
	}

	// stop the IPC service. The service knows SIGINT means shut down so it will
	// stop and release its resources from this signal
	if err := s.cmd.Process.Signal(syscall.SIGINT); err != nil {
		panic(err)
	}

	// remove the socket file
	if err := os.Remove(ipcPath); err != nil {
		// panic(err)
		eprintln(err)
		//} else {
		//	eprintln("removed socket", ipcPath)
	}

	// remove the service binary
	if err := os.Remove(ipcSvcBinPath); err != nil {
		eprintln(err)
	}
}

func (s *ipcState) GenerateKeys() (secret []byte, public []byte) {
	if !s.connected {
		eprintln("attempting to call API without being connected")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	keys, err := s.SignerClient.GenerateKeys(
		ctx,
		&GenerateKeysRequest{},
	)
	if err != nil {
		eprintln(err)
		cancel()
		return nil, nil
	}
	sk, pk := keys.GetSecretKey(), keys.GetPublicKey()
	cancel()
	return sk, pk
}

func (s *ipcState) Sign(sk, pk, msg []byte) (
	signature []byte,
	err error,
) {
	if !s.connected {
		eprintln("attempting to call API without being connected")
		return
	}
	sig, err := s.SignerClient.Sign(context.Background(),
		&SignRequest{
			SecretKey: sk,
			PublicKey: pk,
			Message:   msg,
		},
	)
	if err != nil {
		return nil, err
	}
	sign := sig.GetSignature()
	return sign, nil
}

func (s *ipcState) Verify(apk, sig, msg []byte) (err error) {
	if !s.connected {
		eprintln("attempting to call API without being connected")
		return
	}
	var vr *VerifyResponse
	vr, err = s.SignerClient.Verify(context.Background(),
		&VerifyRequest{
			Apk:       apk,
			Signature: sig,
			Message:   msg,
		},
	)
	if !vr.GetValid() {
		return errors.New("invalid signature")
	}
	return err
}

func (s *ipcState) CreateApk(pk []byte) (apk []byte, err error) {
	if !s.connected {
		eprintln("attempting to call API without being connected")
		return
	}
	var a *CreateAPKResponse
	a, err = s.SignerClient.CreateAPK(context.Background(),
		&CreateAPKRequest{
			PublicKey: pk,
		},
	)
	apk = a.GetAPK()
	return
}

func (s *ipcState) AggregatePk(apk []byte, pks ...[]byte) (
	newApk []byte,
	err error,
) {
	if !s.connected {
		eprintln("attempting to call API without being connected")
		return
	}
	var a *AggregateResponse
	a, err = s.SignerClient.AggregatePK(context.Background(),
		&AggregatePKRequest{
			APK:  apk,
			Keys: pks,
		},
	)
	newApk = a.GetCode()
	return
}

func (s *ipcState) AggregateSig(sig []byte, sigs ...[]byte) (
	aggregatedSig []byte,
	err error,
) {
	if !s.connected {
		eprintln("attempting to call API without being connected")
		return
	}
	var a *AggregateResponse
	a, err = s.SignerClient.AggregateSig(context.Background(),
		&AggregateSigRequest{
			Signature:  sig,
			Signatures: sigs,
		},
	)
	aggregatedSig = a.GetCode()
	return
}
