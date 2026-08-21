//! Product CLI commands: init, assess, report, doctor.

mod assess;
mod doctor;
mod init;
mod report;

pub use assess::{run_assess, AssessCliArgs};
pub use doctor::{run_doctor_cmd, DoctorCliArgs};
pub use init::{run_init, InitCliArgs};
pub use report::{run_report, ReportCliArgs};

use dare_product::ProductError;

use crate::exit_code::{SCANNER_ERROR, UNSUPPORTED_TARGET};

pub(crate) fn map_product_error(err: &ProductError) -> i32 {
    let code = err.exit_code();
    if code == 0 {
        SCANNER_ERROR
    } else if code == 3 {
        UNSUPPORTED_TARGET
    } else {
        code
    }
}
