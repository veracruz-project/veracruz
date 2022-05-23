
fn get1() -> String {
    let client_build = reqwest::blocking::ClientBuilder::new().build().unwrap();
    let ret = match client_build
        .get("http://google.com/")
        .send() {
            Ok(x) => x,
            Err(_) => panic!("xx1"),
        };
    if ret.status() != reqwest::StatusCode::OK {
        panic!("xx2")
    }
    ret.text().unwrap()
}

fn get2() -> String {
    std::thread::spawn(move || {
        get1()
    }).join().unwrap()
}

#[actix_rt::test]
async fn t1() {
    println!("t1 start");
    println!("got {}", get2());
    println!("t1 finish");
}

#[actix_rt::test]
async fn t2() {
    println!("t2 start");
    println!("got {}", get2());
    println!("t2 finish");
}

fn main() {
    let x = actix_rt::Runtime::new().unwrap().block_on(async {
        get2()
    });
    println!("got {}", x)
}
