use clap::{Parser, Subcommand, ValueEnum};
use oci_sdk::{
    auth::{AuthProvider, ConfigFileAuth, InstancePrincipalAuth, OkeWorkloadIdentityAuth},
    CreateRunDetails, DataFlowClient, ListRunsParams,
};

#[derive(Debug, Clone, ValueEnum)]
enum AuthMode {
    /// Use ~/.oci/config file
    Config,
    /// Use instance principal (for OCI VMs)
    InstancePrincipal,
    /// Use OKE workload identity (for Kubernetes)
    WorkloadIdentity,
}

#[derive(Parser)]
#[command(name = "oci-dataflow")]
#[command(about = "OCI Data Flow CLI for triggering and monitoring Spark jobs")]
struct Cli {
    /// OCI region (e.g., us-ashburn-1)
    #[arg(short, long)]
    region: String,

    /// Authentication mode
    #[arg(short, long, value_enum, default_value = "config")]
    auth: AuthMode,

    /// OCI config profile name (only used with --auth=config)
    #[arg(short, long, default_value = "DEFAULT")]
    profile: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List runs in a compartment
    ListRuns {
        /// Compartment OCID
        #[arg(short, long)]
        compartment_id: String,

        /// Filter by application ID
        #[arg(short, long)]
        application_id: Option<String>,

        /// Max results
        #[arg(short, long, default_value = "10")]
        limit: u32,
    },

    /// Get details of a specific run
    GetRun {
        /// Run OCID
        run_id: String,
    },

    /// Create and start a new run
    CreateRun {
        /// Application OCID
        #[arg(short, long)]
        application_id: String,

        /// Compartment OCID
        #[arg(short, long)]
        compartment_id: String,

        /// Display name for the run
        #[arg(short, long)]
        name: Option<String>,

        /// Arguments to pass to the application
        #[arg(long)]
        args: Vec<String>,
    },

    /// Cancel a running job
    CancelRun {
        /// Run OCID
        run_id: String,
    },

    /// List log files for a run
    ListLogs {
        /// Run OCID
        run_id: String,
    },

    /// Download and print a log file
    GetLog {
        /// Run OCID
        run_id: String,

        /// Log file name
        log_name: String,
    },
}

async fn run_command<A: AuthProvider>(
    client: DataFlowClient<A>,
    command: Commands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::ListRuns {
            compartment_id,
            application_id,
            limit,
        } => {
            let params = ListRunsParams {
                application_id,
                limit: Some(limit),
                ..Default::default()
            };
            let runs = client.list_runs(&compartment_id, Some(params)).await?;

            println!("{:<60} {:<15} {:<20}", "ID", "STATE", "NAME");
            println!("{}", "-".repeat(95));
            for run in runs {
                println!(
                    "{:<60} {:<15?} {:<20}",
                    run.id, run.lifecycle_state, run.display_name
                );
            }
        }

        Commands::GetRun { run_id } => {
            let run = client.get_run(&run_id).await?;
            println!("ID:          {}", run.id);
            println!("Name:        {}", run.display_name);
            println!("State:       {:?}", run.lifecycle_state);
            println!("Application: {}", run.application_id);
            println!("Created:     {}", run.time_created);
            println!("Updated:     {}", run.time_updated);
            if let Some(duration) = run.run_duration_in_milliseconds {
                println!("Duration:    {}ms", duration);
            }
            if let Some(details) = run.lifecycle_details {
                println!("Details:     {}", details);
            }
        }

        Commands::CreateRun {
            application_id,
            compartment_id,
            name,
            args,
        } => {
            let mut details = CreateRunDetails::new(&application_id, &compartment_id);
            if let Some(n) = name {
                details = details.display_name(n);
            }
            if !args.is_empty() {
                details = details.arguments(args);
            }

            let run = client.create_run(details).await?;
            println!("Created run: {}", run.id);
            println!("State:       {:?}", run.lifecycle_state);
        }

        Commands::CancelRun { run_id } => {
            let run = client.cancel_run(&run_id).await?;
            println!("Canceling run: {}", run.id);
            println!("State:         {:?}", run.lifecycle_state);
        }

        Commands::ListLogs { run_id } => {
            let logs = client.list_run_logs(&run_id, None, None).await?;

            println!(
                "{:<50} {:<10} {:<15} {:<10}",
                "NAME", "SOURCE", "TYPE", "SIZE"
            );
            println!("{}", "-".repeat(85));
            for log in logs {
                println!(
                    "{:<50} {:<10} {:<15} {} bytes",
                    log.name, log.source, log.log_type, log.size_in_bytes
                );
            }
        }

        Commands::GetLog { run_id, log_name } => {
            let content = client.get_run_log_text(&run_id, &log_name).await?;
            print!("{}", content);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.auth {
        AuthMode::Config => {
            let auth = ConfigFileAuth::from_file(None, Some(cli.profile))?;
            let client = DataFlowClient::new(auth, &cli.region);
            run_command(client, cli.command).await
        }
        AuthMode::InstancePrincipal => {
            let auth = InstancePrincipalAuth::new(Some(cli.region.clone()));
            let client = DataFlowClient::new(auth, &cli.region);
            run_command(client, cli.command).await
        }
        AuthMode::WorkloadIdentity => {
            let auth = OkeWorkloadIdentityAuth::new(cli.region.clone(), None);
            let client = DataFlowClient::new(auth, &cli.region);
            run_command(client, cli.command).await
        }
    }
}
