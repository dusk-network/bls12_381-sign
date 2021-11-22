// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

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

const (
	ipcPath       = "/tmp/bls12381svc.sock"
	ipcSvcBinPath = "/tmp/bls12381svc"
)

// ipcState holds the state of IPC connection
type ipcState struct {
	connected bool
	cmd       *exec.Cmd
	SignerClient
	*grpc.ClientConn
}

var ipc = new(ipcState)

// Connect starts up the GRPC server and connects through a unix socket
func Connect() {
	if ipc.connected {
		return
	}

	// write the IPC service binary to disk
	if _, err := os.Stat(ipcSvcBinPath); os.IsNotExist(err) {
		if err := ioutil.WriteFile(
			ipcSvcBinPath, Binary, 0o700,
		); err != nil {
			panic(err) // not sure what better to do just yet
		}
	}

	// spawn the IPC service
	ipc.cmd = exec.Command(ipcSvcBinPath)

	// command will print output to parent terminal
	ipc.cmd.Stdout = os.Stdout
	ipc.cmd.Stderr = os.Stderr
	if err := ipc.cmd.Start(); err != nil {
		panic(err)
	}

	time.Sleep(time.Second / 4)

	// connect the IPC
	dialer := func(ctx context.Context, path string) (net.Conn, error) {
		return net.Dial("unix", ipcPath)
	}

	var err error
	ipc.ClientConn, err = grpc.Dial(
		"unix://"+ipcPath,
		grpc.WithInsecure(),
		grpc.WithContextDialer(dialer),
	)
	if err != nil {
		panic(err)
	}

	ipc.SignerClient = NewSignerClient(ipc.ClientConn)
	ipc.ClientConn.Connect()
	ipc.connected = true
}

// Disconnect closes the socket, stops the GRPC server and cleans up
func Disconnect() {
	if !ipc.connected {
		return
	}

	//  mark that we are not connected so nobody tries to use this
	ipc.connected = false

	// disconnect the IPC
	if err := ipc.ClientConn.Close(); err != nil {
		eprintln(err)
	}

	// stop the IPC service. The service knows SIGINT means shut down so it will
	// stop and release its resources from this signal
	if err := ipc.cmd.Process.Signal(syscall.SIGINT); err != nil {
		panic(err)
	}

	// remove the socket file
	if err := os.Remove(ipcPath); err != nil {
		eprintln(err)
	}

	// remove the service binary
	if err := os.Remove(ipcSvcBinPath); err != nil {
		eprintln(err)
	}
}

func GenerateKeys() (secret []byte, public []byte) {
	if !ipc.connected {
		eprintln("attempting to call API without being connected")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	keys, err := ipc.SignerClient.GenerateKeys(
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

func Sign(sk, pk, msg []byte) (
	signature []byte,
	err error,
) {
	if !ipc.connected {
		eprintln("attempting to call API without being connected")
		return
	}
	sig, err := ipc.SignerClient.Sign(context.Background(),
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

func Verify(apk, sig, msg []byte) (err error) {
	if !ipc.connected {
		eprintln("attempting to call API without being connected")
		return
	}
	var vr *VerifyResponse
	vr, err = ipc.SignerClient.Verify(context.Background(),
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

func CreateApk(pk []byte) (apk []byte, err error) {
	if !ipc.connected {
		eprintln("attempting to call API without being connected")
		return
	}
	var a *CreateAPKResponse
	a, err = ipc.SignerClient.CreateAPK(context.Background(),
		&CreateAPKRequest{
			PublicKey: pk,
		},
	)
	apk = a.GetAPK()
	return
}

func AggregatePk(apk []byte, pks ...[]byte) (
	newApk []byte,
	err error,
) {
	if !ipc.connected {
		eprintln("attempting to call API without being connected")
		return
	}
	var a *AggregateResponse
	a, err = ipc.SignerClient.AggregatePK(context.Background(),
		&AggregatePKRequest{
			APK:  apk,
			Keys: pks,
		},
	)
	newApk = a.GetCode()
	return
}

func AggregateSig(sig []byte, sigs ...[]byte) (
	aggregatedSig []byte,
	err error,
) {
	if !ipc.connected {
		eprintln("attempting to call API without being connected")
		return
	}
	var a *AggregateResponse
	a, err = ipc.SignerClient.AggregateSig(context.Background(),
		&AggregateSigRequest{
			Signature:  sig,
			Signatures: sigs,
		},
	)
	aggregatedSig = a.GetCode()
	return
}

func eprintln(args ...interface{}) {
	_, _ = fmt.Fprint(os.Stderr, "cli: ")
	_, _ = fmt.Fprintln(os.Stderr, args...)
}
