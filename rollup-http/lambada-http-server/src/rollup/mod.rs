// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use lazy_static::lazy_static;
use libc::c_void;
use regex::Regex;
use serde::{Deserialize, Serialize};
use validator::Validate;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[derive(Clone)]
pub struct RollupFd(*mut cmt_rollup_t);

impl RollupFd {
    pub fn create() -> Result<Self, i32> {
        unsafe {
            let zeroed = Box::leak(Box::new(std::mem::zeroed::<cmt_rollup_t>()));
            let result = cmt_rollup_init(zeroed);
            if result != 0 {
                Err(result)
            } else {
                Ok(RollupFd(zeroed))
            }
        }
    }
}

impl Drop for RollupFd {
    fn drop(&mut self) {
        unsafe {
            cmt_rollup_fini(self.0);
            drop(Box::from_raw(self.0));
        }
    }
}

unsafe impl Sync for RollupFd {}
unsafe impl Send for RollupFd {}

pub const REQUEST_TYPE_ADVANCE_STATE: u32 = 0;
pub const REQUEST_TYPE_INSPECT_STATE: u32 = 1;
pub const CARTESI_ROLLUP_ADDRESS_SIZE: u32 = 20;

lazy_static! {
    static ref ETH_ADDR_REGEXP: Regex = Regex::new(r"0x[0-9a-fA-F]{1,42}$").unwrap();
    static ref ETH_U256_REGEXP: Regex = Regex::new(r"0x[0-9a-fA-F]{1,64}$").unwrap();
}

#[derive(Debug, Default)]
pub struct RollupError {
    message: String,
}

impl RollupError {
    pub fn new(message: &str) -> Self {
        RollupError {
            message: String::from(message),
        }
    }
}

impl std::fmt::Display for RollupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rollup error: {}", &self.message)
    }
}

impl std::error::Error for RollupError {}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct GIORequest {
    #[validate(range(min = 0x10))] // avoid overlapping with our HTIF_YIELD_MANUAL_REASON_*
    pub domain: u16,
    pub payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GIOResponse {
    pub response_code: u16,
    pub response: String,
}

pub fn rollup_throw_exception(
    fd: &RollupFd,
    exception: &Exception,
) -> Result<(), Box<dyn std::error::Error>> {
    print_exception(exception);

    let binary_payload = match hex::decode(&exception.payload[2..]) {
        Ok(payload) => payload,
        Err(_err) => {
            return Err(Box::new(RollupError::new(&format!(
                "Error decoding report payload, payload must be in Ethereum hex binary format"
            ))));
        }
    };

    let mut buffer: Vec<u8> = Vec::with_capacity(binary_payload.len());
    let length = binary_payload.len();
    let data = buffer.as_mut_ptr() as *mut c_void;

    let res = unsafe {
        std::ptr::copy(
            binary_payload.as_ptr(),
            buffer.as_mut_ptr(),
            binary_payload.len(),
        );
        cmt_rollup_emit_exception(fd.0, length as u32, data)
    };
    if res != 0 {
        return Err(Box::new(RollupError::new(&format!(
            "IOCTL_ROLLUP_THROW_EXCEPTION returned error {}",
            res
        ))));
    } else {
        log::debug!("exception successfully thrown!");
    }
    Ok(())
}

pub fn print_exception(exception: &Exception) {
    log::debug!(
        "exception: {{ length: {} payload: {}}}",
        exception.payload.len(),
        exception.payload
    );
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct Exception {
    pub payload: String,
}

pub enum RollupResponse {
    Finish(bool),
}
