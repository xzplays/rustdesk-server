// https://tools.ietf.org/rfc/rfc5128.txt
// https://blog.csdn.net/bytxl/article/details/44344855

use flexi_logger::*;
use hbb_common::{bail, config::RENDEZVOUS_PORT, ResultType};
use hbbs::{common::*, *};

const RMEM: usize = 0;

fn main() -> ResultType<()> {
    let _logger = Logger::try_with_env_or_str("info")?
        .log_to_stdout()
        .format(opt_format)
        .write_mode(WriteMode::Async)
        .start()?;
    let args = format!(
        "-c --config=[FILE] +takes_value 'Sets a custom config file'
        -b, --bind=[IP] 'Sets the IP address to bind to (default: all interfaces)'
        -p, --port=[NUMBER(default={RENDEZVOUS_PORT})] 'Sets the listening port'
        -s, --serial=[NUMBER(default=0)] '[DEPRECATED] Sets configure update serial number'
        -R, --rendezvous-servers=[HOSTS] '[DEPRECATED] Sets rendezvous servers, separated by comma'
        -u, --software-url=[URL] '[DEPRECATED] Sets download url of RustDesk software of newest version'
        -r, --relay-servers=[HOST] 'Sets the default relay servers, separated by comma'
        -M, --rmem=[NUMBER(default={RMEM})] 'Sets UDP recv buffer size, set system rmem_max first, e.g., sudo sysctl -w net.core.rmem_max=52428800. vi /etc/sysctl.conf, net.core.rmem_max=52428800, sudo sysctl –p'
        , --mask=[MASK] '[DEPRECATED] Determine if the connection comes from LAN, e.g. 192.168.0.0/16'
        -k, --key=[KEY] 'Only allow the client with the same key'
        --must-login=[MODE] 'Require a client login before punch hole: off|api|local (default: off)'
        --api-server=[URL] 'API server used by must-login=api (default: http://127.0.0.1:31114)'
        --api-verify-secret=[SECRET] 'Shared secret for /api/server/verify-token'
        --api-jwt-key=[KEY] 'HS256 key for must-login=local (default: env RUSTDESK_API_JWT_KEY)'",
    );
    init_args(&args, "hbbs", "RustDesk ID/Rendezvous Server");
    let port = get_arg_or("port", RENDEZVOUS_PORT.to_string()).parse::<i32>()?;
    if port < 3 {
        bail!("Invalid port");
    }
    let bind_addr = parse_bind_address(&get_arg("bind"))?;
    let rmem = get_arg("rmem").parse::<usize>().unwrap_or(RMEM);
    let serial: i32 = get_arg("serial").parse().unwrap_or(0);
    crate::common::check_software_update();
    RendezvousServer::start_with_bind(
        bind_addr,
        port,
        serial,
        &get_arg_or("key", "-".to_owned()),
        rmem,
    )?;
    Ok(())
}
