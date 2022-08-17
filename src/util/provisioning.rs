use trussed::types::{Location, PathBuf};

/// Checks whether we have any certificates installed in certstore. This is used
/// to detect whether Fobnail has been provisioned.
pub fn is_token_provisioned<T>(trussed: &mut T) -> bool
where
    T: trussed::client::FilesystemClient,
{
    let cert_dir = PathBuf::from(b"/cert/");
    let result = trussed::syscall!(trussed.read_dir_first(Location::Internal, cert_dir, None));
    result.entry.is_some()
}
