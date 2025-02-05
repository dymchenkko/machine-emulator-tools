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

extern crate nix;

use std::os::unix::io::RawFd;
use std::sync::Arc;

use actix_web::{web, middleware::Logger, web::Data, web::Bytes, web::Json, App, HttpResponse, HttpServer};
use async_mutex::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::config::Config;
use crate::rollup;
use crate::rollup::{
    AdvanceRequest, Exception, InspectRequest, Notice, Report, RollupRequest, Voucher
};
use std::os::fd::FromRawFd;
use std::io::{Write, Read};
use cid::Cid;
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient,TryFromUri};
use futures::TryStreamExt;
use std::io::{Seek, SeekFrom};

use std::os::unix::io::AsRawFd;
use nix::{ioctl_readwrite, fcntl::OFlag};

#[repr(align(4096))]
struct Aligned([u8; 4096 as usize]);

use std::{
    fs::{OpenOptions, File},
    os::unix::fs::OpenOptionsExt,
};

const HTIF_DEVICE_YIELD: u8 = 2;
const HTIF_YIELD_AUTOMATIC: u8 = 0;
const HTIF_YIELD_REASON_PROGRESS: u16 = 0;
const HTIF_YIELD_REASON_EXCEPTION: u16 = 6;

const READ_BLOCK: u64 = 0x00001;
const EXCEPTION: u64 = 0x00002;
const GET_TX: u64 = 0x00003;
const FINISH: u64 = 0x00004;
const WRITE_BLOCK: u64 = 0x000005;
const GET_APP: u64 = 0x00006;
const HINT: u64 = 0x00007;


#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "request_type")]
enum RollupHttpRequest {
    #[serde(rename = "advance_state")]
    Advance { data: AdvanceRequest },
    #[serde(rename = "inspect_state")]
    Inspect { data: InspectRequest },
}

/// Create new instance of http server
pub fn create_server(
    config: &Config,
    rollup_fd: Arc<Mutex<RawFd>>,
) -> std::io::Result<actix_server::Server> {
    let server = HttpServer::new(move || {
        let data = Data::new(Mutex::new(Context {
            rollup_fd: rollup_fd.clone(),
        }));
        App::new()
            .app_data(data)
            .wrap(Logger::default())
            .service(exception)
            .service(finish)
            .service(ipfs_put)
            .service(ipfs_get)
            .service(ipfs_has)
            .service(get_tx)
            .service(get_app)
            .service(hint)
    })
    .bind((config.http_address.as_str(), config.http_port))
    .map(|t| t)?
    .run();
    Ok(server)
}

/// Create and run new instance of http server
pub async fn run(
    config: &Config,
    rollup_fd: Arc<Mutex<RawFd>>,
    server_ready: Arc<Notify>,
) -> std::io::Result<()> {
    log::info!("starting http dispatcher http service!");
    let server = create_server(config, rollup_fd)?;
    server_ready.notify_one();
    server.await
}

#[actix_web::put("/ipfs/put/{cid}")]
async fn ipfs_put(content: Bytes, cid: web::Path<String>) -> HttpResponse {
    let cid = cid.into_inner();
    let mut file = File::create(&(std::env::var("CACHE_DIR").unwrap() + &cid)).expect("Failed to create file");
    file.write_all(&content.to_vec())
        .expect("Failed to write to file");

    let file = File::create(&(std::env::var("STORE_DIR").unwrap() + &cid)).expect("Failed to create file");
    HttpResponse::Ok().finish()
}

#[actix_web::get("/get_tx")]
async fn get_tx() -> HttpResponse {

    let mut file = OpenOptions::new()
        .write(true)
        .open(std::env::var("IO_DEVICE").unwrap()).unwrap();

    file.seek(SeekFrom::Start(0)).unwrap();
    file.write(&GET_TX.to_be_bytes()).unwrap();
    file.sync_all().unwrap();

    do_yield(HTIF_YIELD_REASON_PROGRESS);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT)
        .open(std::env::var("IO_DEVICE").unwrap()).unwrap();

    file.seek(SeekFrom::End(0)).unwrap();

    let file_length = file.stream_position().unwrap() as usize;

    let mut buffer: Vec<u8> = Vec::with_capacity(file_length);

    file.seek(SeekFrom::Start(0)).unwrap();

    for i in (0..file_length).step_by(4096) {
        let mut out_buf = Aligned([0; 4096 as usize]);
        file.read_exact(&mut out_buf.0).unwrap();
        buffer.extend_from_slice(&out_buf.0); 
    }

    assert_eq!(buffer.len() % 512, 0);

    let mut length_cid = [0u8; 8];

    length_cid.copy_from_slice(&buffer[0..8]);
    let length_cid = u64::from_be_bytes(length_cid) as usize;

    let mut cid = vec![0u8; length_cid];
    cid.copy_from_slice(&buffer[8..8+length_cid]);

    let mut length_payload = [0u8; 8];

    length_payload.copy_from_slice(&buffer[16 + length_cid..16 + length_cid + 8]);
    let length_payload = u64::from_be_bytes(length_payload) as usize;

    let mut payload = vec![0u8; length_payload];

    payload.copy_from_slice(&buffer[24 + length_cid..24 + length_cid + length_payload]);

    let mut length_app_cid = [0u8; 8];

    length_app_cid.copy_from_slice(&buffer[24 + length_cid + length_payload ..32 + length_cid + length_payload]);
    let length_app_cid = u64::from_be_bytes(length_app_cid) as usize;

    let mut app_cid = vec![0u8; length_app_cid as usize];
    app_cid.copy_from_slice(&buffer[32 + length_cid + length_payload..32 + length_cid + length_payload + length_app_cid]);

    let endpoint = "http://127.0.0.1:5001".to_string();
    let client = IpfsClient::from_str(&endpoint).unwrap();
    let cid = Cid::try_from(cid).unwrap();
    let app_cid = Cid::try_from(app_cid).unwrap();

    let ipfs_app_cid = client.files_stat("/app").await.unwrap().hash;
    let ipfs_app_cid = Cid::try_from(ipfs_app_cid).unwrap();

    assert_eq!(app_cid, ipfs_app_cid);

    client.files_cp(&cid.to_string(), "/state-new").await.unwrap();
    client.files_mv("/state", "/previous");
    client.files_rm("/state", true).await.unwrap();
    client.files_mv("/state-new", "/state");

    HttpResponse::Ok()
        .append_header((hyper::header::CONTENT_TYPE, "application/octet-stream"))
        .body(payload) 
}

#[actix_web::get("/get_app")]
async fn get_app() -> HttpResponse {

    let mut file = OpenOptions::new()
        .write(true)
        .open(std::env::var("IO_DEVICE").unwrap()).unwrap();

    file.seek(SeekFrom::Start(0)).unwrap();
    file.write(&GET_APP.to_be_bytes()).unwrap();
    file.sync_all().unwrap();

    do_yield(HTIF_YIELD_REASON_PROGRESS);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT)
        .open(std::env::var("IO_DEVICE").unwrap()).unwrap();

    file.seek(SeekFrom::End(0)).unwrap();

    let file_length = file.stream_position().unwrap() as usize;

    let mut buffer: Vec<u8> = Vec::with_capacity(file_length);

    file.seek(SeekFrom::Start(0)).unwrap();

    for i in (0..file_length).step_by(4096) {
        let mut out_buf = Aligned([0; 4096 as usize]);
        file.read_exact(&mut out_buf.0).unwrap();
        buffer.extend_from_slice(&out_buf.0); 
    }

    assert_eq!(buffer.len() % 512, 0);

    let mut length_cid = [0u8; 8];

    length_cid.copy_from_slice(&buffer[0..8]);
    let length_cid = u64::from_be_bytes(length_cid);

    let mut cid = vec![0u8; length_cid as usize];
    cid.copy_from_slice(&buffer[8..8+length_cid as usize]);

    let endpoint = "http://127.0.0.1:5001".to_string();
    let client = IpfsClient::from_str(&endpoint).unwrap();
    let cid = Cid::try_from(cid).unwrap();

    client.files_cp(&cid.to_string(), "/app-new").await.unwrap();
    client.files_rm("/app", true).await.unwrap();
    client.files_mv("/app-new", "/app");
    HttpResponse::Ok().finish()
}

#[actix_web::get("/ipfs/get/{cid}")]
async fn ipfs_get(cid: web::Path<String>, data: Data<Mutex<Context>>) -> HttpResponse {
    let cid = cid.into_inner();
    match File::open(&(std::env::var("CACHE_DIR").unwrap() + &cid))
    {
        Ok(mut file) => {
            let mut response = vec![];
            match file.read_to_end(&mut response) {
                Ok(_) => {
                    HttpResponse::Ok().body(response)
                },
                Err(err) => {
                    HttpResponse::BadRequest().body(format!("failed to get data: {:?}", err))
                },
            }
        },
        Err(err) =>{

            let mut file = OpenOptions::new()
            .write(true)
            .open(std::env::var("IO_DEVICE").unwrap()).unwrap();

            file.seek(SeekFrom::Start(0)).unwrap();
            file.write(&READ_BLOCK.to_be_bytes()).unwrap();
            let cid_bytes = Cid::try_from(cid).unwrap().to_bytes();
            let cid_length = cid_bytes.len() as u64;
            file.seek(SeekFrom::Start(8)).unwrap();
            file.write(&cid_length.to_be_bytes()).unwrap();
            file.seek(SeekFrom::Start(16)).unwrap();
            file.write(&cid_bytes).unwrap();

            file.sync_all().unwrap();

            do_yield(HTIF_YIELD_REASON_PROGRESS);

            println!("back from yield");

            let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECT)
            .open(std::env::var("IO_DEVICE").unwrap()).unwrap();

            file.seek(SeekFrom::End(0)).unwrap();

            let file_length = file.stream_position().unwrap() as usize;

            let mut buffer: Vec<u8> = Vec::with_capacity(file_length);

            file.seek(SeekFrom::Start(0)).unwrap();

            for i in (0..file_length).step_by(4096) {
                let mut out_buf = Aligned([0; 4096 as usize]);
                file.read_exact(&mut out_buf.0).unwrap();
                buffer.extend_from_slice(&out_buf.0); 
            }

            assert_eq!(buffer.len() % 512, 0);

            let mut length_buf = [0u8; 8];
            length_buf.copy_from_slice(&buffer[0..8]);
            let length = u64::from_be_bytes(length_buf);
            println!("length in buffer {:?}", length);

            let mut data = vec![0u8; length as usize];
            data.copy_from_slice(&buffer[16..16 + length as usize]);

            HttpResponse::Ok()
            .append_header((hyper::header::CONTENT_TYPE, "application/octet-stream"))
            .body(data) 
        }
    }
}

#[actix_web::post("/hint")]
async fn hint(payload: Bytes) -> HttpResponse {
    let mut file = OpenOptions::new()
        .write(true)
        .open(std::env::var("IO_DEVICE").unwrap()).unwrap();

    file.seek(SeekFrom::Start(0)).unwrap();
    file.write(&HINT.to_be_bytes()).unwrap();

    let payload_len = payload.len();

    file.seek(SeekFrom::Start(8)).unwrap();
    file.write(&payload_len.to_be_bytes()).unwrap();

    file.seek(SeekFrom::Start(16)).unwrap();
    file.write(&payload.slice(0..payload.len())).unwrap();

    file.sync_all().unwrap();

    do_yield(HTIF_YIELD_REASON_PROGRESS);
    HttpResponse::Ok().finish()
}

#[actix_web::head("/ipfs/has/{cid}")]
async fn ipfs_has(cid: web::Path<String>) -> HttpResponse {
    HttpResponse::new(actix_web::http::StatusCode::from_u16(200).unwrap())
}

/// Process voucher request from DApp, write voucher to rollup device
#[actix_web::post("/voucher")]
async fn voucher(mut voucher: Json<Voucher>, data: Data<Mutex<Context>>) -> HttpResponse {
    return HttpResponse::BadRequest().body("vouchers not valid in lambada mode");
}

/// Process notice request from DApp, write notice to rollup device
#[actix_web::post("/notice")]
async fn notice(mut notice: Json<Notice>, data: Data<Mutex<Context>>) -> HttpResponse {
    return HttpResponse::BadRequest().body("notices not valid in lambada mode");
}

/// Process report request from DApp, write report to rollup device
#[actix_web::post("/report")]
async fn report(report: Json<Report>, data: Data<Mutex<Context>>) -> HttpResponse {
    return HttpResponse::BadRequest().body("reports not valid in lambada mode");
}

/// The DApp should call this method when it cannot proceed with the request processing after an exception happens.
/// This method should be the last method ever called by the DApp backend, and it should not expect the call to return.
/// The Rollup HTTP Server will pass the exception info to the Cartesi Server Manager.
#[actix_web::post("/exception")]
async fn exception(exception: Json<Exception>, data: Data<Mutex<Context>>) -> HttpResponse {

    let mut file = OpenOptions::new()
    .write(true)
    .open(std::env::var("IO_DEVICE").unwrap()).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write(&EXCEPTION.to_be_bytes()).unwrap();

    let exception_data = exception.payload.as_bytes();

    let exception_length = exception_data.len() as u64;
    file.seek(SeekFrom::Start(8)).unwrap();
    file.write(&exception_length.to_be_bytes()).unwrap();

    file.seek(SeekFrom::Start(16)).unwrap();
    file.write(&exception_data).unwrap();
    file.sync_all().unwrap();

    do_yield(HTIF_YIELD_REASON_EXCEPTION);

    HttpResponse::Ok().finish()

}

/// Process finish request from DApp, write finish to rollup device
/// and pass RollupFinish struct to linux rollup advance/inspect requests loop thread
#[actix_web::post("/finish")]
async fn finish(finish: Json<FinishRequest>, data: Data<Mutex<Context>>) -> HttpResponse {

    let mut file = OpenOptions::new()
    .write(true)
    .open(std::env::var("IO_DEVICE").unwrap()).unwrap();

    file.seek(SeekFrom::Start(0)).unwrap();
    file.write(&FINISH.to_be_bytes()).unwrap();
    let accept: u64 = match finish.status.as_str() {
        "accept" => 0,
        "reject" => 1,
        _ => {
            return HttpResponse::BadRequest().body("status must be 'accept' or 'reject'");
        }
    };

    file.seek(SeekFrom::Start(8)).unwrap();
    file.write(&accept.to_be_bytes()).unwrap();

    let endpoint = "http://127.0.0.1:5001".to_string();
    let client = IpfsClient::from_str(&endpoint).unwrap();
    let cid = client.files_stat("/state").await.unwrap().hash;
    let cid = Cid::try_from(cid).unwrap();
    let cid_bytes = cid.to_bytes();

    let cid_length = cid_bytes.len() as u64;
    file.seek(SeekFrom::Start(16)).unwrap();
    file.write(&cid_length.to_be_bytes()).unwrap();

    file.seek(SeekFrom::Start(24)).unwrap();
    file.write(&cid_bytes).unwrap();
    file.sync_all().unwrap();

    do_yield(HTIF_YIELD_REASON_PROGRESS);

    let dir = std::env::var("STORE_DIR").unwrap();
    let paths = std::fs::read_dir(dir).unwrap();

    for path in paths {
        let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path.unwrap().path()).unwrap();
        let mut buffer = vec![];
        file.read_to_end(&mut buffer).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write(&WRITE_BLOCK.to_be_bytes()).unwrap();

        let file_len = buffer.len().to_be_bytes();

        file.seek(SeekFrom::Start(8)).unwrap();
        file.write(&file_len).unwrap();

        file.seek(SeekFrom::Start(16)).unwrap();
        file.write(&buffer).unwrap();
        file.sync_all().unwrap();

        do_yield(HTIF_YIELD_REASON_PROGRESS);
    }
    HttpResponse::Ok().finish()
}

fn do_yield(reason: u16) {
    
        let file = File::open("/dev/yield").unwrap();
        let fd = file.as_raw_fd();

        let mut data = YieldRequest {
            dev: HTIF_DEVICE_YIELD,
            cmd: HTIF_YIELD_AUTOMATIC,
            reason,
            data: 0,
        };

        unsafe {
            ioctl_yield(fd, &mut data).unwrap();
        }
}

#[derive(Debug, Clone, Deserialize)]
struct FinishRequest {
    status: String,
}

#[derive(Debug, Clone, Serialize)]
struct IndexResponse {
    index: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ErrorDescription {
    code: u16,
    reason: String,
    description: String,
}

#[derive(Debug, Serialize)]
struct Error {
    error: ErrorDescription,
}

struct Context {
    pub rollup_fd: Arc<Mutex<RawFd>>,
}

#[repr(C)]
pub struct YieldRequest {
    dev: u8,
    cmd: u8,
    reason: u16,
    data: u32,
}
ioctl_readwrite!(ioctl_yield, 0xd1, 0, YieldRequest);