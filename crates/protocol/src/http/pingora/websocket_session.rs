// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Bounded message I/O for an admitted downstream WebSocket.

use std::io::{self, Read, Write};

use bytes::{Buf as _, Bytes};
use tungstenite::{
    Error, Message, WebSocket,
    protocol::{Role, WebSocketConfig},
};

use super::local_upgrade::LocalWebSocket;

/// Maximum assembled message or single frame size.
const MESSAGE_LIMIT: usize = 1_048_576; // 1 MiB
/// Maximum encoded write, including frame headers and a pending control reply.
const WRITE_LIMIT: usize = 1_049_088;

/// Buffer and size limits shared by the downstream codec.
fn codec_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(8192)
        .write_buffer_size(0)
        .max_write_buffer_size(WRITE_LIMIT)
        .max_message_size(Some(MESSAGE_LIMIT))
        .max_frame_size(Some(MESSAGE_LIMIT))
}

/// Nonblocking codec input and output. Only the driver touches the transport.
#[derive(Default)]
struct Wire {
    /// The current transport chunk, consumed before polling the transport again.
    input: Bytes,
    /// Encoded bytes waiting for the driver to write them.
    output: Vec<u8>,
}

impl Read for Wire {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        if self.input.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let count = buf.len().min(self.input.len());
        buf.write_all(&self.input.copy_to_bytes(count))?;
        Ok(count)
    }
}

impl Write for Wire {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.output.len().saturating_add(buf.len()) > WRITE_LIMIT {
            return Err(io::Error::other("WebSocket output limit exceeded"));
        }
        self.output.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Complete WebSocket data messages handled one at a time.
pub struct WebSocketSession<'a> {
    /// Borrowed wire transport from the local upgrade.
    transport: LocalWebSocket<'a>,
    /// Server codec, with masking checks, fragmentation and control handling.
    codec: WebSocket<Wire>,
    /// Closed, failed, or a write in progress that may have been cancelled.
    terminal: bool,
}

impl<'a> WebSocketSession<'a> {
    /// Start message I/O after a successful local upgrade.
    pub fn new(transport: LocalWebSocket<'a>) -> Self {
        Self {
            transport,
            codec: WebSocket::from_raw_socket(Wire::default(), Role::Server, Some(codec_config())),
            terminal: false,
        }
    }

    /// Receive a complete data message, answering control frames internally.
    ///
    /// Cancelling while a control reply is being written makes the session
    /// terminal. End the request if cancellation may have interrupted a write.
    /// Subsequent reads return `None` and sends return `AlreadyClosed`.
    ///
    /// # Errors
    /// Returns a transport or protocol error. End the request on error.
    pub async fn receive(&mut self) -> tungstenite::Result<Option<Message>> {
        while !self.terminal {
            let event = self.codec.read();
            match event {
                Ok(Message::Text(_) | Message::Binary(_)) => return event.map(Some),
                Ok(Message::Close(_)) | Err(Error::ConnectionClosed) => {
                    self.flush_codec().await?;
                    self.terminal = true;
                },
                Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {
                    self.flush_codec().await?;
                },
                Err(Error::Io(err)) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.flush_output().await?;
                    self.read_wire().await?;
                },
                Err(err) => {
                    self.terminal = true;
                    return Err(err);
                },
            }
        }
        Ok(None)
    }

    /// Send a complete text or binary message directly to the downstream.
    ///
    /// Cancelling a pending send makes the session terminal. End the request
    /// after cancellation. Subsequent reads return `None` and sends return
    /// `AlreadyClosed`.
    ///
    /// # Errors
    /// Returns an error for a closed session, unsupported message or failed write.
    pub async fn send(&mut self, message: Message) -> tungstenite::Result<()> {
        if self.terminal {
            return Err(Error::AlreadyClosed);
        }
        if !matches!(message, Message::Text(_) | Message::Binary(_)) || message.len() > MESSAGE_LIMIT {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid outbound WebSocket message",
            )));
        }
        self.terminal = true;
        self.codec.send(message)?;
        self.flush_output().await
    }

    /// Supply another wire chunk or terminate on transport failure.
    async fn read_wire(&mut self) -> tungstenite::Result<()> {
        let error = match self.transport.read().await {
            Ok(Some(chunk)) => {
                self.codec.get_mut().input = chunk;
                return Ok(());
            },
            Ok(None) => Error::Io(io::ErrorKind::UnexpectedEof.into()),
            Err(error) => transport_error(error),
        };
        self.terminal = true;
        Err(error)
    }

    /// Flush protocol-generated control replies.
    async fn flush_codec(&mut self) -> tungstenite::Result<()> {
        self.terminal = true;
        match self.codec.flush() {
            Ok(()) | Err(Error::ConnectionClosed) => self.flush_output().await,
            Err(err) => Err(err),
        }
    }

    /// Await downstream backpressure without a queue. An interrupted write is terminal.
    async fn flush_output(&mut self) -> tungstenite::Result<()> {
        self.terminal = true;
        let output = std::mem::take(&mut self.codec.get_mut().output);
        if !output.is_empty() {
            self.transport
                .write(Bytes::from(output))
                .await
                .map_err(transport_error)?;
        }
        self.terminal = false;
        Ok(())
    }
}

/// Convert Pingora's transport error into the codec's error type.
fn transport_error(error: Box<pingora_core::Error>) -> Error {
    Error::Io(io::Error::other(error))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    /// A large binary frame header with a mask of all zeroes.
    fn binary_header(length: u64, opcode: u8) -> Vec<u8> {
        let mut header = vec![opcode, 0xFF];
        header.extend_from_slice(&length.to_be_bytes());
        header.extend_from_slice(&[0; 4]);
        header
    }

    #[test]
    fn frame_limit_accepts_boundary_and_rejects_larger_header() {
        let mut wire = binary_header(1_048_576, 0x82);
        wire.extend(vec![7; MESSAGE_LIMIT]);
        let mut codec = WebSocket::from_raw_socket(Cursor::new(wire), Role::Server, Some(codec_config()));
        assert!(matches!(codec.read(), Ok(Message::Binary(payload)) if payload.len() == MESSAGE_LIMIT));

        let wire = binary_header(1_048_577, 0x82);
        let mut codec = WebSocket::from_raw_socket(Cursor::new(wire), Role::Server, Some(codec_config()));
        assert!(matches!(codec.read(), Err(Error::Capacity(_))));
    }

    #[test]
    fn message_limit_counts_bytes_across_fragments() {
        let mut wire = binary_header(1_048_576, 0x02);
        wire.extend(vec![7; MESSAGE_LIMIT]);
        wire.extend_from_slice(b"\x80\x81\0\0\0\0x");
        let mut codec = WebSocket::from_raw_socket(Cursor::new(wire), Role::Server, Some(codec_config()));
        assert!(matches!(codec.read(), Err(Error::Capacity(_))));
    }
}
