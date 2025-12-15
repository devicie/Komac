use std::collections::BTreeSet;

use winget_types::installer::{ExpectedReturnCodes, InstallerReturnCode, ReturnResponse};

pub fn expected_return_codes() -> BTreeSet<ExpectedReturnCodes> {
    use ReturnResponse::*;

    [
        (-1, CancelledByUser),
        (1, InvalidParameter),
        (1150, SystemNotSupported),
        (1201, DiskFull),
        (1203, InvalidParameter),
        (1601, ContactSupport),
        (1602, CancelledByUser),
        (1618, InstallInProgress),
        (1623, SystemNotSupported),
        (1625, BlockedByPolicy),
        (1628, InvalidParameter),
        (1633, SystemNotSupported),
        (1638, AlreadyInstalled),
        (1639, InvalidParameter),
        (1640, BlockedByPolicy),
        (1641, RebootInitiated),
        (1643, BlockedByPolicy),
        (1644, BlockedByPolicy),
        (1649, BlockedByPolicy),
        (1650, InvalidParameter),
        (1654, SystemNotSupported),
        (3010, RebootRequiredToFinish),
    ]
    .iter()
    .map(|&(code, response)| ExpectedReturnCodes {
        installer_return_code: InstallerReturnCode::new(code),
        return_response: response,
        return_response_url: None,
    })
    .collect()
}
