// enumrust-mcp - MCP server for EnumRust security scanner

use async_trait::async_trait;
use rust_mcp_sdk::{
    error::SdkResult,
    mcp_server::{server_runtime, McpServerOptions, ServerHandler},
    schema::*,
    *,
};
use std::sync::Arc;

mod tools;

#[derive(Default)]
struct EnumRustHandler {}

#[async_trait]
impl ServerHandler for EnumRustHandler {
    async fn handle_list_tools_request(
        &self,
        _request: Option<PaginatedRequestParams>,
        _runtime: Arc<dyn McpServer>,
    ) -> std::result::Result<ListToolsResult, RpcError> {
        Ok(ListToolsResult {
            tools: tools::EnumRustTools::tools(),
            meta: None,
            next_cursor: None,
        })
    }

    async fn handle_call_tool_request(
        &self,
        params: CallToolRequestParams,
        _runtime: Arc<dyn McpServer>,
    ) -> std::result::Result<CallToolResult, CallToolError> {
        let tool: tools::EnumRustTools = params.try_into()?;
        let output = match &tool {
            tools::EnumRustTools::SubdomainEnumTool(t) => {
                let mut cmd = t.call_tool();
                cmd.output().map_err(CallToolError::new)?
            }
            tools::EnumRustTools::DnsResolveTool(t) => {
                let mut cmd = t.call_tool();
                cmd.output().map_err(CallToolError::new)?
            }
            tools::EnumRustTools::IpScanTool(t) => {
                let mut cmd = t.call_tool();
                cmd.output().map_err(CallToolError::new)?
            }
            tools::EnumRustTools::HttpProbeTool(t) => {
                let mut cmd = t.call_tool();
                cmd.output().map_err(CallToolError::new)?
            }
            tools::EnumRustTools::JsCrawlTool(t) => {
                let mut cmd = t.call_tool();
                cmd.output().map_err(CallToolError::new)?
            }
            tools::EnumRustTools::AdminFinderTool(t) => {
                let mut cmd = t.call_tool();
                cmd.output().map_err(CallToolError::new)?
            }
            tools::EnumRustTools::SecretsScanTool(t) => {
                let mut cmd = t.call_tool();
                cmd.output().map_err(CallToolError::new)?
            }
            tools::EnumRustTools::VulnScanTool(t) => {
                let mut cmd = t.call_tool();
                cmd.output().map_err(CallToolError::new)?
            }
            tools::EnumRustTools::WordPressScanTool(t) => {
                let mut cmd = t.call_tool();
                cmd.output().map_err(CallToolError::new)?
            }
            tools::EnumRustTools::InfoDisclosureTool(t) => {
                let mut cmd = t.call_tool();
                cmd.output().map_err(CallToolError::new)?
            }
            tools::EnumRustTools::FullScanTool(t) => {
                let mut cmd = t.call_tool();
                cmd.output().map_err(CallToolError::new)?
            }
        };

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(CallToolResult::text_content(vec![TextContent::from(stdout)]))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            Err(CallToolError::from_message(format!("Scan failed: {}", stderr)))
        }
    }
}

#[tokio::main]
async fn main() -> SdkResult<()> {
    let server_details = InitializeResult {
        server_info: Implementation {
            name: "enumrust-mcp".into(),
            version: "0.1.0".into(),
            title: Some("EnumRust Security Scanner MCP Server".into()),
            description: Some("MCP server for EnumRust - comprehensive security scanner".into()),
            icons: vec![],
            website_url: Some("https://github.com/KingOfBugbounty/enumrust".into()),
        },
        capabilities: ServerCapabilities {
            tools: Some(ServerCapabilitiesTools { list_changed: None }),
            ..Default::default()
        },
        protocol_version: ProtocolVersion::V2025_11_25.into(),
        instructions: Some(
            "EnumRust MCP Server provides security scanning capabilities including subdomain enumeration, port scanning, vulnerability scanning, and more.".into(),
        ),
        meta: None,
    };

    let transport = StdioTransport::new(TransportOptions::default())?;
    let handler = EnumRustHandler::default().to_mcp_server_handler();
    let server = server_runtime::create_server(McpServerOptions {
        transport,
        handler,
        server_details,
        task_store: None,
        client_task_store: None,
        message_observer: None,
    });
    server.start().await
}