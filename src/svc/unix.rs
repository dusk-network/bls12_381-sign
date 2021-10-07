// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(not(target_os = "windows"))]
#[cfg(std)]
use std::{
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(std)]
use {
    tokio::io::ReadBuf,
    tokio::io::{AsyncRead, AsyncWrite},
    tonic::transport::server::Connected,
};

#[cfg(std)]
#[derive(Debug)]
pub struct UnixStream(pub tokio::net::UnixStream);

#[cfg(std)]
#[derive(Clone)]
pub struct UnixStreamConnectInfo {
    // Metadata about your connection
}

#[cfg(std)]
impl Connected for UnixStream {
    type ConnectInfo = UnixStreamConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        UnixStreamConnectInfo {}
    }
}

#[cfg(std)]
impl AsyncRead for UnixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

#[cfg(std)]
impl AsyncWrite for UnixStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
