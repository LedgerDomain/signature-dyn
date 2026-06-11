use std::borrow::Cow;

use crate::SignatureBytes;

pub trait SignatureT {
    fn jose_algorithm(&self) -> &'static str;
    fn get_raw_bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]>;
    fn to_signature_bytes<'b, 's: 'b>(&'s self) -> SignatureBytes<'b> {
        SignatureBytes::new(self.jose_algorithm(), self.get_raw_bytes())
            .expect("Failed to create SignatureBytes")
    }
}
