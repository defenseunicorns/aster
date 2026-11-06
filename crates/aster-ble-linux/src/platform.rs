pub(crate) mod discovery;
pub(crate) mod socket;

pub use socket::{
    BluezSocketFactory, OpenFuture, OpenedContact, SocketFactory, open_contact,
    open_contact_with_factory,
};
