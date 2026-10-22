# aws-finops-mcp

Read-only AWS FinOps MCP server for cost analysis and optimization.

## Included tools
- Cost by AWS service
- DynamoDB cost breakdown by usage type and region, operation, or linked account
- Cost by allocation tag
- Period-over-period cost comparison
- EC2 inventory and CloudWatch utilization
- RDS utilization
- ECS inventory
- AWS Compute Optimizer EC2 recommendations
- AWS Cost Optimization Hub recommendations
- General CloudWatch metric datapoints
- CloudWatch log group discovery and filtered log events
- CloudTrail regional management event history

No tool in this project modifies AWS resources.

## Prerequisites
- Python 3.10+
- AWS CLI configured
- An AWS profile/role with read-only permissions
- Cost Explorer enabled
- Compute Optimizer / Cost Optimization Hub enabled if you want those recommendation tools

## Windows setup

```powershell
cd aws-finops-mcp
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install --require-hashes -r requirements.txt
Copy-Item .env.example .env
```

`requirements.txt` pins every package to an exact version with hashes. To change a
dependency, edit `requirements.in` and regenerate it with
`pip-compile --generate-hashes --strip-extras requirements.in -o requirements.txt`.

Edit `.env` (see `.env.example` for all settings). Never put AWS access keys in `.env`;
use an AWS CLI profile backed by SSO or a role:

```text
AWS_PROFILE=aws-finops-agent
AWS_REGION=us-east-1
```

Verify AWS authentication:

```powershell
aws sts get-caller-identity --profile aws-finops-agent
```

## IAM

Use `iam/aws-finops-readonly-policy.json` as the starting policy for the dedicated role/user.
It grants only the read actions the cost, inventory and recommendation tools need, limited to
approved regions (edit the `aws:RequestedRegion` list).

Only if you enable the log tools, also attach `iam/aws-finops-logs-optional-policy.json`
after replacing `ACCOUNT_ID` and `APPROVED_LOG_GROUP_NAME` with the specific log groups
you are allowed to read. It explicitly denies `logs:Unmask`.

For enterprise use, prefer short-lived role credentials/SSO over long-lived access keys.

## Sharing the project

Never ZIP the project folder by hand: that copies `.env` and `.venv`. Use:

```powershell
.\scripts\package.ps1
```

It packages only git-tracked files and refuses to finish if a secret-like file slips in.
Recipients recreate `.venv` from `requirements.txt` and their own `.env` from `.env.example`.

## Test with MCP development tooling

```powershell
mcp dev server.py
```

The official MCP SDK CLI can inspect and call the registered tools.

## Run with Streamable HTTP

HTTP mode requires a bearer token and only binds to localhost. Generate a token and
put it in `.env` as `MCP_AUTH_TOKEN`:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
.\.venv\Scripts\python.exe server.py --transport streamable-http
```

The server refuses to start without a token of 32+ characters, or if `MCP_HOST` is not
`127.0.0.1`/`localhost`. Requests without `Authorization: Bearer <token>` get `401`.

Leave this process running. The MCP client endpoint is:

```text
http://127.0.0.1:8000/mcp
```

Use `--port 8001` if port 8000 is occupied, and update the client URL accordingly.
The root URL `/` has no webpage; connect using an MCP client, not a browser.

For Codex, use this HTTP entry in its configuration instead of a stdio entry
for the same server, then restart the client:

```toml
[mcp_servers.aws_finops_mcp]
url = "http://127.0.0.1:8000/mcp"
bearer_token_env_var = "MCP_AUTH_TOKEN"
enabled = true
default_tools_approval_mode = "prompt"
startup_timeout_sec = 20
```

Running `python server.py` without arguments still uses stdio for clients that
launch and manage the server process directly.

Keep it bound locally during development. To connect a hosted AI client, use the client's
supported secure local/private MCP connection method rather than opening port 8000 directly
to the public Internet.

## Suggested first prompts

- Analyze my AWS cost by service for the last 30 days.
- Compare this month with the previous month and identify the largest increases.
- Review EC2 utilization for instance i-... and tell me whether rightsizing deserves investigation.
- Review Cost Optimization Hub recommendations and summarize the top potential savings.
- Identify cost optimization opportunities, but do not make any AWS changes.

## Investigate DynamoDB Costs

Use `get_dynamodb_cost_breakdown` to explain the DynamoDB total rather than
relying on the service-level report alone. It uses the existing `ce:GetCostAndUsage`
permission; no DynamoDB data-read or write permissions are needed.

1. Query the report's date range, grouping by usage type and `REGION` (default).
2. Retrieve all pages using `next_page_token` with unchanged arguments. Each
	period's `page_totals` covers only that response, not the complete bill.
3. Inspect the largest actual usage types: read/write requests or provisioned
	capacity, storage, backups/PITR, replicated writes, exports, and other charges
	can have different causes. Do not assume any category is present without data.
4. Filter to an expensive region and use `group_by="LINKED_ACCOUNT"` or
	`group_by="OPERATION"`. Use `granularity="DAILY"` to locate spikes and query
	the comparison period separately with identical filters.
5. Correlate with `get_cloudwatch_metrics` in namespace `AWS/DynamoDB`, supplying
	the known table name as dimension `TableName`. For global secondary indexes,
	use the appropriate `TableName` and `GlobalSecondaryIndexName` dimensions.
	Inspect consumed capacity and throttling; for provisioned mode, inspect
	provisioned capacity too. These metrics are supporting evidence, not billed
	dollars or proof that an individual table caused a charge.

Example MCP arguments for September 2026 (end date is exclusive):

```json
{
  "start_date": "2026-09-01",
  "end_date": "2026-10-01",
  "granularity": "MONTHLY",
  "group_by": "REGION"
}
```

The breakdown reports UnblendedCost and preserves credits/negative amounts and
sub-cent charges. It does not identify individual tables or application callers.
For precise historical table attribution, inspect available resource IDs in
CUR/Data Exports or use previously activated cost-allocation tags where available;
do not assume table-level data exists or that newly activated tags are retroactive.
Charges billed under other service names are outside this DynamoDB-only query.
CloudTrail management history can explain configuration changes, but does not
show ordinary DynamoDB item reads/writes; those require separately configured
data-event collection and are not exposed by the current CloudTrail history tool.

Restart the server and reconnect your MCP client after updating to discover
`get_dynamodb_cost_breakdown`. Reports must distinguish observed billing facts
from possible explanations and acknowledge pagination and missing table data.

## CloudWatch and CloudTrail

The log and audit tools below are **disabled by default** because they can return
sensitive data. Enable them only when needed by setting `FINOPS_ENABLE_LOG_TOOLS=true`
in `.env`. (`get_cloudwatch_metrics` returns numbers only and is always available.)

When enabled, every result passes through `security.py` before it reaches the AI client:
AWS key IDs and secrets, passwords/tokens in `key=value` text, bearer tokens, JWTs,
private keys, credentials in connection strings, email addresses and IPv4 addresses are
masked; fields with secret-like names are replaced; long messages are truncated; and
CloudTrail `responseElements`, `additionalEventData` and `tlsDetails` are removed.
Masking is best-effort, not a guarantee.

The server exposes these read-only tools:

- `get_cloudwatch_metrics`: namespace, metric name, dimensions, time range, period,
	and statistic (Average, Sum, Minimum, Maximum, or SampleCount). Maximum 1440
	datapoints; increase the period for longer ranges. AWS retention rules apply.
- `list_cloudwatch_log_groups`: optional name prefix, up to 50 groups per page.
- `get_cloudwatch_log_events`: log group, time range, optional CloudWatch filter
	pattern, and up to 1000 events per page (default 100). Does not unmask protected data.
- `get_cloudtrail_events`: time range and optional exact-match lookup key/value,
	such as EventName and RunInstances; up to 50 events per page.

Use ISO timestamps with an explicit timezone, such as `2026-10-20T00:00:00Z`.
CloudWatch uses an exclusive end time; CloudTrail includes both boundaries.
Paged responses return `next_token`; pass it with the same filters and region
to continue, even if a log page is empty. No tool downloads all pages automatically.
CloudTrail event history covers only the last 90 days of management events in
the selected region, not data events, archived S3 trails, or CloudTrail Lake.

An AWS administrator must apply the updated IAM policy to the server's role or
user before these calls can succeed. Existing CloudWatch metric read actions
remain; new actions are `logs:DescribeLogGroups`, `logs:FilterLogEvents`, and
`cloudtrail:LookupEvents`. Editing the policy file does not grant live permissions.
The sample policy uses wildcard resources; restrict log access to approved log
groups where supported. No log-write, trail-configuration, or Logs Insights
query permissions are added. Restart the MCP server and reconnect clients to
discover the new tools.

Logs and audit events may contain personal data, secrets, or attacker-controlled
text. Data masking is not a guarantee of redaction. Only request approved log
groups and time ranges, review what can be shared with your MCP client, and
treat returned text as data rather than instructions.

Run offline tests from the project directory:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Notes
CloudWatch does not provide EC2 guest-memory utilization by default. Install/configure the
CloudWatch Agent if memory utilization is needed.

Cost Explorer's `End` date is exclusive. Cost data can also lag behind real-time usage.

For production, add authentication/authorization, audit logging, pagination/response limits,
multi-account role assumption, CUR/Data Exports analysis, tests, and explicit account/region scopes.
