use anyhow::{bail, Context, Result};
use clap::{ArgGroup, Parser};
use futures::{stream, StreamExt};
use ipnet::Ipv4Net;
use std::{
    env,
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr},
    process,
    time::Duration,
};
use tokio::{
    net::TcpStream,
    time::timeout,
};

const FAST_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 465, 500, 514, 515, 587, 631, 636, 993, 995,
    1080, 1433, 1521, 1723, 2049, 2375, 2376, 3000, 3306, 3389, 5432, 5601,
    5900, 5985, 5986, 6379, 8000, 8080, 8081, 8443, 8888, 9200, 27017,
];

const DISCOVERY_PORTS: &[u16] = &[
    22, 80, 135, 139, 443, 445, 3389, 8080, 8443,
];

#[derive(Parser, Debug)]
#[command(
    name = "rust-network-scanner",
    version,
    about = "Escáner TCP básico para redes y laboratorios autorizados"
)]
#[command(group(
    ArgGroup::new("scan_mode")
        .required(true)
        .multiple(false)
        .args(["sn", "fast", "all_ports"])
))]
struct Args {
    /// Red IPv4 en formato CIDR. Ejemplo: 192.168.18.0/24
    target: Ipv4Net,

    /// Descubrir hosts mediante pruebas TCP
    #[arg(long)]
    sn: bool,

    /// Escanear una lista de puertos comunes
    #[arg(short = 'F', long = "fast")]
    fast: bool,

    /// Escanear todos los puertos TCP, del 1 al 65535
    #[arg(long = "all-ports")]
    all_ports: bool,

    /// Número máximo de conexiones simultáneas
    #[arg(short = 'c', long, default_value_t = 500)]
    concurrency: usize,

    /// Tiempo máximo por conexión, en milisegundos
    #[arg(short = 't', long, default_value_t = 500)]
    timeout_ms: u64,

    /// No realizar descubrimiento previo antes de escanear puertos
    #[arg(long)]
    no_discovery: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeResult {
    Open,
    Closed,
    Unreachable,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("[!] Error: {error:#}");
        process::exit(1);
    }
}

async fn run() -> Result<()> {
    /*
     * Clap no interpreta "-p-" como una bandera normal.
     * Reemplazamos ese argumento por "--all-ports" antes de analizarlo.
     */
    let cli_args = normalize_arguments();
    let args = Args::parse_from(cli_args);

    if args.concurrency == 0 {
        bail!("La concurrencia debe ser mayor que cero");
    }

    if args.timeout_ms == 0 {
        bail!("El timeout debe ser mayor que cero");
    }

    let hosts: Vec<Ipv4Addr> = args.target.hosts().collect();

    if hosts.is_empty() {
        bail!("La red indicada no contiene direcciones utilizables");
    }

    /*
     * Evita escanear accidentalmente redes demasiado grandes.
     * /16 contiene aproximadamente 65 534 hosts utilizables.
     */
    if hosts.len() > 65_536 {
        bail!(
            "La red contiene {} hosts. Utiliza una red /16 o más pequeña",
            hosts.len()
        );
    }

    let timeout_duration = Duration::from_millis(args.timeout_ms);

    println!("Rust Network Scanner");
    println!("====================");
    println!("[*] Red: {}", args.target);
    println!("[*] Hosts: {}", hosts.len());
    println!("[*] Concurrencia: {}", args.concurrency);
    println!("[*] Timeout: {} ms", args.timeout_ms);
    println!();

    if args.sn {
        discover_network(
            hosts,
            timeout_duration,
            args.concurrency,
        )
        .await;

        return Ok(());
    }

    let scan_targets = if args.no_discovery {
        hosts
    } else {
        println!("[*] Realizando descubrimiento TCP previo...");
        let alive = discover_hosts(
            hosts,
            timeout_duration,
            args.concurrency,
            false,
        )
        .await;

        println!(
            "[*] Hosts potencialmente activos: {}\n",
            alive.len()
        );

        alive
    };

    if scan_targets.is_empty() {
        println!("[-] No se detectaron hosts activos.");
        println!(
            "    Prueba nuevamente con --no-discovery si el objetivo filtra los puertos de detección."
        );
        return Ok(());
    }

    if args.fast {
        scan_network(
            scan_targets,
            FAST_PORTS.to_vec(),
            timeout_duration,
            args.concurrency,
        )
        .await;
    } else if args.all_ports {
        scan_network(
            scan_targets,
            (1..=u16::MAX).collect(),
            timeout_duration,
            args.concurrency,
        )
        .await;
    }

    Ok(())
}

/*
 * Permite utilizar exactamente:
 *
 *     scanner 192.168.18.0/24 -p-
 *
 * Internamente se transforma en:
 *
 *     scanner 192.168.18.0/24 --all-ports
 */
fn normalize_arguments() -> Vec<String> {
    env::args()
        .map(|argument| {
            if argument == "-p-" {
                "--all-ports".to_string()
            } else {
                argument
            }
        })
        .collect()
}

async fn discover_network(
    hosts: Vec<Ipv4Addr>,
    timeout_duration: Duration,
    concurrency: usize,
) {
    println!("[*] Descubriendo hosts mediante TCP...\n");

    let alive = discover_hosts(
        hosts,
        timeout_duration,
        concurrency,
        true,
    )
    .await;

    println!();
    println!("[*] Descubrimiento finalizado");
    println!("[*] Hosts detectados: {}", alive.len());
}

async fn discover_hosts(
    hosts: Vec<Ipv4Addr>,
    timeout_duration: Duration,
    concurrency: usize,
    show_results: bool,
) -> Vec<Ipv4Addr> {
    stream::iter(hosts)
        .map(|host| async move {
            let alive = is_host_alive(host, timeout_duration).await;
            (host, alive)
        })
        .buffer_unordered(concurrency)
        .filter_map(|(host, alive)| async move {
            if alive {
                if show_results {
                    println!("[+] Host activo: {host}");
                }

                Some(host)
            } else {
                None
            }
        })
        .collect()
        .await
}

async fn is_host_alive(
    host: Ipv4Addr,
    timeout_duration: Duration,
) -> bool {
    /*
     * Limitamos la concurrencia interna para evitar lanzar todos
     * los puertos de descubrimiento simultáneamente por cada host.
     */
    stream::iter(DISCOVERY_PORTS.iter().copied())
        .map(|port| async move {
            probe_port(host, port, timeout_duration).await
        })
        .buffer_unordered(4)
        .any(|result| async move {
            matches!(result, ProbeResult::Open | ProbeResult::Closed)
        })
        .await
}

async fn scan_network(
    hosts: Vec<Ipv4Addr>,
    ports: Vec<u16>,
    timeout_duration: Duration,
    concurrency: usize,
) {
    println!(
        "[*] Escaneando {} puerto(s) en {} host(s)...",
        ports.len(),
        hosts.len()
    );

    for host in hosts {
        println!();
        println!("Escaneo de {host}");
        println!("{}", "-".repeat(38));

        let open_ports = scan_host(
            host,
            &ports,
            timeout_duration,
            concurrency,
        )
        .await;

        if open_ports.is_empty() {
            println!("[-] No se encontraron puertos abiertos");
            continue;
        }

        for port in &open_ports {
            println!(
                "[+] {:>5}/tcp abierto  {}",
                port,
                common_service(*port)
            );
        }

        println!(
            "[*] Total de puertos abiertos: {}",
            open_ports.len()
        );
    }
}

async fn scan_host(
    host: Ipv4Addr,
    ports: &[u16],
    timeout_duration: Duration,
    concurrency: usize,
) -> Vec<u16> {
    let mut open_ports: Vec<u16> = stream::iter(ports.iter().copied())
        .map(|port| async move {
            let result = probe_port(host, port, timeout_duration).await;
            (port, result)
        })
        .buffer_unordered(concurrency)
        .filter_map(|(port, result)| async move {
            if result == ProbeResult::Open {
                Some(port)
            } else {
                None
            }
        })
        .collect()
        .await;

    open_ports.sort_unstable();
    open_ports
}

async fn probe_port(
    host: Ipv4Addr,
    port: u16,
    timeout_duration: Duration,
) -> ProbeResult {
    let address = SocketAddr::from((host, port));

    match timeout(
        timeout_duration,
        TcpStream::connect(address),
    )
    .await
    {
        Ok(Ok(stream)) => {
            drop(stream);
            ProbeResult::Open
        }

        /*
         * "Connection refused" indica que el host respondió,
         * aunque el puerto esté cerrado.
         */
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => {
            ProbeResult::Closed
        }

        Ok(Err(_)) | Err(_) => ProbeResult::Unreachable,
    }
}

fn common_service(port: u16) -> &'static str {
    match port {
        20 => "FTP data",
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        69 => "TFTP",
        80 => "HTTP",
        110 => "POP3",
        111 => "RPCBind",
        123 => "NTP",
        135 => "MSRPC",
        137..=139 => "NetBIOS",
        143 => "IMAP",
        161 | 162 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        500 => "ISAKMP",
        514 => "Syslog",
        515 => "LPD",
        587 => "SMTP submission",
        631 => "IPP",
        636 => "LDAPS",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "Microsoft SQL Server",
        1521 => "Oracle",
        1723 => "PPTP",
        2049 => "NFS",
        2375 | 2376 => "Docker",
        3000 => "HTTP development",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5601 => "Kibana",
        5900 => "VNC",
        5985 => "WinRM HTTP",
        5986 => "WinRM HTTPS",
        6379 => "Redis",
        8000 | 8080 | 8081 => "HTTP alternate",
        8443 => "HTTPS alternate",
        8888 => "HTTP alternate",
        9200 => "Elasticsearch",
        27017 => "MongoDB",
        _ => "desconocido",
    }
}
