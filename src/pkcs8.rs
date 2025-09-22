use crate::Result;

pub trait PKCS8Read {
    /// Read a PKCS#8 PEM file and produce an instance of this type.
    fn read_from_pkcs8_pem_file(path: &std::path::Path) -> Result<Self>
    where
        Self: Sized;
}

pub trait PKCS8Write {
    /// Write this to a PKCS#8 PEM file.
    fn write_to_pkcs8_pem_file(&self, path: &std::path::Path) -> Result<()>;
}
