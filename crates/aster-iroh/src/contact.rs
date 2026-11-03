use aster_contact::{
    CarrierPeerEvidence, ChannelBindingCapability, ContactError, ContactErrorKind, ContactFuture,
    ContactRequestHandler, OrderedContact, StableCarrierId,
};

use crate::{CarrierError, Connection};

fn map_carrier_error(error: CarrierError) -> ContactError {
    let kind = match error {
        CarrierError::Configuration(_) => ContactErrorKind::Configuration,
        CarrierError::Transport(_) => ContactErrorKind::Transport,
        CarrierError::Timeout(_) => ContactErrorKind::Timeout,
        CarrierError::UnauthorizedPeer(_) => ContactErrorKind::Unauthorized,
        CarrierError::FrameTooLarge { .. } | CarrierError::TurnTooLarge { .. } => {
            ContactErrorKind::Bounds
        }
    };
    ContactError::new(kind, error.to_string())
}

impl OrderedContact for Connection {
    fn peer_evidence(&self) -> CarrierPeerEvidence {
        CarrierPeerEvidence::AuthenticatedCarrier {
            stable_carrier_id: StableCarrierId::new(*self.remote_id().as_bytes()),
            channel_binding: ChannelBindingCapability::Derivable,
        }
    }

    fn max_frame_bytes(&self) -> usize {
        self.max_exchange_bytes()
    }

    fn request_with_total_limit<'a>(
        &'a self,
        request: &'a [u8],
        total_limit: usize,
    ) -> ContactFuture<'a, Vec<u8>> {
        Box::pin(async move {
            Connection::request_with_total_limit(self, request, total_limit)
                .await
                .map_err(map_carrier_error)
        })
    }

    fn respond_once_with_total_limit<'a>(
        &'a self,
        total_limit: usize,
        handler: ContactRequestHandler<'a>,
    ) -> ContactFuture<'a, bool> {
        Box::pin(async move {
            let mut handler_error = None;
            let result = Connection::respond_once_with_total_limit(self, total_limit, |request| {
                handler(request).map_err(|error| {
                    handler_error = Some(error);
                    CarrierError::Transport("ordered contact handler rejected request".into())
                })
            })
            .await;
            match handler_error {
                Some(error) => Err(error),
                None => result.map_err(map_carrier_error),
            }
        })
    }

    fn finish_as_initiator(&self) -> ContactFuture<'_, ()> {
        Box::pin(async move {
            Connection::finish_as_initiator(self)
                .await
                .map_err(map_carrier_error)
        })
    }

    fn finish_as_responder(&self) -> ContactFuture<'_, ()> {
        Box::pin(async move {
            Connection::finish_as_responder(self)
                .await
                .map_err(map_carrier_error)
        })
    }

    fn close(&self) {
        self.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Endpoint, EndpointConfig, ExpectedPeer, SecretKey};
    use aster_contact::{CarrierPeerEvidence, ChannelBindingCapability, ContactErrorKind};
    use std::collections::BTreeSet;

    fn loopback(endpoint: &Endpoint) -> std::net::SocketAddr {
        endpoint
            .bound_sockets()
            .into_iter()
            .find(std::net::SocketAddr::is_ipv4)
            .expect("IPv4 loopback binding")
    }

    async fn contact_pair_with_max_exchange(
        max_exchange_bytes: usize,
    ) -> (Endpoint, Endpoint, Connection, Connection) {
        let mut config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        config.max_exchange_bytes = max_exchange_bytes;
        let server = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("server");
        let client = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("client");
        let allowed = BTreeSet::from([client.id()]);
        let accept = tokio::spawn({
            let server = server.clone();
            async move { server.accept(&allowed).await.expect("accept") }
        });
        let client_contact = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect");
        let server_contact = accept.await.expect("accept task");
        (server, client, server_contact, client_contact)
    }

    async fn contact_pair() -> (Endpoint, Endpoint, Connection, Connection) {
        contact_pair_with_max_exchange(crate::DEFAULT_MAX_EXCHANGE_BYTES).await
    }

    #[tokio::test]
    async fn ordered_contact_reports_authenticated_iroh_evidence() {
        let (server, client, server_contact, client_contact) = contact_pair().await;

        assert_eq!(
            <Connection as OrderedContact>::peer_evidence(&client_contact),
            CarrierPeerEvidence::AuthenticatedCarrier {
                stable_carrier_id: aster_contact::StableCarrierId::new(*server.id().as_bytes()),
                channel_binding: ChannelBindingCapability::Derivable,
            }
        );
        assert_eq!(
            <Connection as OrderedContact>::peer_evidence(&server_contact)
                .stable_carrier_id()
                .expect("authenticated identity")
                .as_bytes(),
            client.id().as_bytes()
        );

        client_contact.close();
        server_contact.close();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn ordered_contact_preserves_bounded_request_response_and_finish() {
        let (server, client, server_contact, client_contact) = contact_pair().await;
        let responder = tokio::spawn(async move {
            let first_handler: ContactRequestHandler<'_> = Box::new(|request| {
                assert_eq!(request, b"non-final-request");
                Ok((b"non-final-response".to_vec(), false))
            });
            assert!(
                !<Connection as OrderedContact>::respond_once_with_total_limit(
                    &server_contact,
                    128,
                    first_handler,
                )
                .await
                .expect("respond non-final")
            );
            let final_handler: ContactRequestHandler<'_> = Box::new(|request| {
                assert_eq!(request, b"final-request");
                Ok((b"ring-one-response".to_vec(), true))
            });
            assert!(
                <Connection as OrderedContact>::respond_once_with_total_limit(
                    &server_contact,
                    128,
                    final_handler,
                )
                .await
                .expect("respond final")
            );
            <Connection as OrderedContact>::finish_as_responder(&server_contact)
                .await
                .expect("finish responder");
        });

        let non_final_response = <Connection as OrderedContact>::request_with_total_limit(
            &client_contact,
            b"non-final-request",
            128,
        )
        .await
        .expect("non-final request");
        assert_eq!(non_final_response, b"non-final-response");
        let response = <Connection as OrderedContact>::request_with_total_limit(
            &client_contact,
            b"final-request",
            128,
        )
        .await
        .expect("final request");
        assert_eq!(response, b"ring-one-response");
        <Connection as OrderedContact>::finish_as_initiator(&client_contact)
            .await
            .expect("finish initiator");
        responder.await.expect("responder task");

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn ordered_contact_advertises_and_accepts_configured_exchange_ceiling() {
        let maximum = crate::DEFAULT_MAX_EXCHANGE_BYTES + 1;
        let (server, client, server_contact, client_contact) =
            contact_pair_with_max_exchange(maximum).await;
        assert_eq!(
            <Connection as OrderedContact>::max_frame_bytes(&client_contact),
            maximum
        );
        let responder = tokio::spawn(async move {
            let handler: ContactRequestHandler<'_> = Box::new(move |request| {
                assert_eq!(request.len(), maximum);
                Ok((Vec::new(), false))
            });
            <Connection as OrderedContact>::respond_once_with_total_limit(
                &server_contact,
                maximum,
                handler,
            )
            .await
            .expect("respond at configured ceiling");
            server_contact.close();
        });

        let response = <Connection as OrderedContact>::request_with_total_limit(
            &client_contact,
            &vec![0x5a; maximum],
            maximum,
        )
        .await
        .expect("request at configured ceiling");
        assert!(response.is_empty());
        responder.await.expect("responder task");

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn ordered_contact_abort_cannot_prove_responder_completion() {
        let (server, client, server_contact, client_contact) = contact_pair().await;
        let responder = tokio::spawn(async move {
            let handler: ContactRequestHandler<'_> =
                Box::new(|_| Ok((b"final-response".to_vec(), true)));
            assert!(
                <Connection as OrderedContact>::respond_once_with_total_limit(
                    &server_contact,
                    128,
                    handler,
                )
                .await
                .expect("respond final")
            );
            <Connection as OrderedContact>::close(&server_contact);
        });

        let response = <Connection as OrderedContact>::request_with_total_limit(
            &client_contact,
            b"final-request",
            128,
        )
        .await
        .expect("final request");
        assert_eq!(response, b"final-response");
        let error = <Connection as OrderedContact>::finish_as_initiator(&client_contact)
            .await
            .expect_err("abort must not prove orderly completion");
        assert_eq!(error.kind(), ContactErrorKind::Transport);
        responder.await.expect("responder task");

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn ordered_contact_maps_oversized_request_to_bounds() {
        let (server, client, server_contact, client_contact) = contact_pair().await;
        let maximum = <Connection as OrderedContact>::max_frame_bytes(&client_contact);
        let error = <Connection as OrderedContact>::request_with_total_limit(
            &client_contact,
            &vec![0x5a; maximum + 1],
            usize::MAX,
        )
        .await
        .expect_err("oversized request");
        assert_eq!(error.kind(), ContactErrorKind::Bounds);

        client_contact.close();
        server_contact.close();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn ordered_contact_handler_rejection_never_reports_completion() {
        let (server, client, server_contact, client_contact) = contact_pair().await;
        let responder = tokio::spawn(async move {
            let handler: ContactRequestHandler<'_> = Box::new(|_| {
                Err(ContactError::new(
                    ContactErrorKind::Protocol,
                    "rejected test request",
                ))
            });
            let error = <Connection as OrderedContact>::respond_once_with_total_limit(
                &server_contact,
                128,
                handler,
            )
            .await
            .expect_err("handler rejection");
            assert_eq!(error.kind(), ContactErrorKind::Protocol);
            server_contact.close();
        });

        let request = <Connection as OrderedContact>::request_with_total_limit(
            &client_contact,
            b"rejected",
            128,
        )
        .await;
        assert!(request.is_err());
        responder.await.expect("responder task");

        client.close().await;
        server.close().await;
    }
}
