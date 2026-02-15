use std::collections::BTreeSet;

use winget_types::installer::{ExpectedReturnCodes, InstallerReturnCode, ReturnResponse};

const COMMON_CODES: &[(i32, ReturnResponse)] = {
    use ReturnResponse::*;
    &[
        (-1, CancelledByUser),
        (1, InvalidParameter),
        (1150, SystemNotSupported),
        (1201, DiskFull),
        (1203, InvalidParameter),
        (3010, RebootRequiredToFinish),
    ]
};

const MSI_CODES: &[(i32, ReturnResponse)] = {
    use ReturnResponse::*;
    &[
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
    ]
};

pub fn expected_return_codes(msi_based: bool) -> BTreeSet<ExpectedReturnCodes> {
    let codes: Box<dyn Iterator<Item = &(i32, ReturnResponse)>> = if msi_based {
        Box::new(COMMON_CODES.iter().chain(MSI_CODES))
    } else {
        Box::new(COMMON_CODES.iter())
    };

    codes
        .map(|&(code, response)| ExpectedReturnCodes {
            installer_return_code: InstallerReturnCode::new(code),
            return_response: response,
            return_response_url: None,
        })
        .collect()
}
