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

extern crate lambada_http_server;
extern crate rollup_http_client;
extern crate rollup_http_server;
extern crate test_gio_server;
use crate::rollup::GIOResponse;
use actix_server::ServerHandle;
use async_mutex::Mutex;
use lambada_http_server::config::Config;
use lambada_http_server::rollup::RollupFd;
use lambada_http_server::*;
use rand::Rng;
use rollup_http_client::rollup::GIORequest;
use rstest::*;
use std::future::Future;
use std::sync::Arc;
use test_gio_server::start_server;
use tokio::sync::oneshot;
use tokio::task;
use tokio::task::JoinHandle;
const HOST: &str = "127.0.0.1";
#[allow(dead_code)]
struct Context {
    lambada_address: String,
    lambada_server_handle: actix_server::ServerHandle,
}

impl Drop for Context {
    fn drop(&mut self) {
        // Shut down http server+
        println!("shutting down http service in drop cleanup");
    }
}

fn run_test_lambada_http_service(
    host: &str,
    port: u16,
) -> std::io::Result<Option<actix_server::ServerHandle>> {
    let rollup_fd: Arc<Mutex<RollupFd>> = Arc::new(Mutex::new(RollupFd::create().unwrap()));
    let rollup_fd = rollup_fd.clone();
    let http_config = Config {
        http_address: host.to_string(),
        http_port: port,
    };
    println!("Creating lambada http server");
    let server = http_service::create_server(&http_config, rollup_fd)?;
    let server_handle = server.handle();
    println!("Spawning lambada http server");
    tokio::spawn(server);
    println!("Http lambada server spawned");
    Ok(Some(server_handle))
}
#[rstest]
#[tokio::test]
async fn test_server() {
    let (tx, rx) = oneshot::channel();
    let server_task = task::spawn(start_server(tx));
    let _ = rx.await.expect("Server failed to start");
    let gio_request = GIORequest {
        domain: 0x100,
        payload: hex::encode(vec![0, 0, 0]),
    };
    let client = hyper::Client::new();

    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .uri("http://127.0.0.1:5004/gio")
        .body(hyper::Body::from(
            serde_json::to_string(&gio_request).unwrap(),
        ))
        .expect("gio request");
    client.request(req).await.unwrap();
    drop(server_task);
}

#[fixture]
async fn context_future() -> Context {
    let mut server_handle: Option<ServerHandle> = None;
    let mut server_handle2: Option<JoinHandle<()>> = None;
    let mut count = 5;
    let mut port;
    port = 5005;

    match run_test_lambada_http_service(HOST, port) {
        Ok(handle) => {
            server_handle = handle;
        }
        Err(ex) => {
            eprint!("Error instantiating rollup http service {}", ex.to_string());
            if count > 0 {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    };
    count = count - 1;
    Context {
        lambada_address: format!("http://{}:{}", HOST, port),
        lambada_server_handle: server_handle.unwrap(),
    }
}

#[rstest]
#[tokio::test]
async fn test_server_instance_creation(
    context_future: impl Future<Output = Context>,
) -> Result<(), Box<dyn std::error::Error>> {
    let context = context_future.await;
    println!("Sleeping in the test... ");
    std::thread::sleep(std::time::Duration::from_secs(5));
    println!("End sleeping");
    println!("Shutting down http service");
    context.lambada_server_handle.stop(true).await;
    println!("Http server closed");
    Ok(())
}

#[rstest]
#[tokio::test]
async fn test_open_state(
    context_future: impl Future<Output = Context>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (tx, rx) = oneshot::channel();
    let server_task = task::spawn(start_server(tx));
    let _ = rx.await.expect("Server failed to start");
    let context = context_future.await;
    let client = hyper::Client::new();
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .uri(context.lambada_address.clone() + "/open_state")
        .body(hyper::Body::empty())
        .expect("open_state request");
    match client.request(req).await {
        Ok(gio_response) => {
            let body = hyper::body::to_bytes(gio_response)
                .await
                .expect("error get response from rollup_http_server qio request")
                .to_vec();
            println!("result {:?}", String::from_utf8(body.clone()));
        }
        Err(e) => {
            println!("failed to handle gio_response request: {}", e);
        }
    }

    context.lambada_server_handle.stop(true).await;
    drop(server_task);

    Ok(())
}

#[rstest]
#[tokio::test]
async fn test_commit_state(
    context_future: impl Future<Output = Context>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (tx, rx) = oneshot::channel();
    let server_task = task::spawn(start_server(tx));
    let _ = rx.await.expect("Server failed to start");
    let context = context_future.await;
    let client = hyper::Client::new();
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .uri(context.lambada_address.clone() + "/commit_state")
        .body(hyper::Body::empty())
        .expect("commit_state request");
    match client.request(req).await {
        Ok(res) => {
            let body = hyper::body::to_bytes(res)
                .await
                .expect("error get response from rollup_http_server qio request")
                .to_vec();
            println!("result {:?}", String::from_utf8(body.clone()));

            //println!("got commit_state response: {:?}", res);
        }
        Err(e) => {
            println!(
                "failed to send commit_state request to lambada http server: {}",
                e
            );
        }
    }
    context.lambada_server_handle.stop(true).await;
    drop(server_task);
    Ok(())
}
