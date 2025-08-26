# AWS EC2 IR Containment Script

An automated **Incident Response containment script** for AWS EC2 instances.  
This script isolates a potentially compromised EC2 instance by detaching it from Auto Scaling, taking EBS snapshots, applying an isolation Security Group, replacing IAM instance profile with a Deny-All role, and generating forensic reports.  

## Features
- Automatic **detachment from Auto Scaling Group**
- **EBS snapshot** creation for forensic analysis
- **Metadata collection** and summary reports
- **Network isolation** using a dedicated Security Group
- **IAM Deny-All role** attachment to block API calls
- **Tagging** of the compromised instance with incident details
- **DRY_RUN mode** for safe testing

## Checklist (Script Workflow)
1. Validate AWS CLI, jq, and credentials
2. Collect instance details (state, IPs, IAM, ENIs)
3. Detach instance from Auto Scaling Group (if applicable)
4. Snapshot all attached EBS volumes
5. Save metadata (JSON, TSV, SG mapping)
6. Create or reuse an **Isolation Security Group** with no ingress/egress
7. Attach the isolation SG to all ENIs
8. Create or reuse IAM **Deny-All role & instance profile**
9. Replace instance profile with the deny-all profile
10. Tag the instance and generate a full **containment report**

## Usage

### Prerequisites
- **AWS CLI** (`aws --version`)
- **jq** (`jq --version`)
- IAM permissions (see below)
- Configured AWS credentials (`aws configure`)

### Basic run
./EC2Shield.sh --region eu-central-1 --instance-id i-0123456789abcdef


### With Incident ID and custom output directory

./EC2Shield.sh --region eu-central-1 --instance-id i-0123456789abcdef --incident-id IR-2025-001 --out-dir /tmp/ir_outputs

### Dry run (simulation only, no real changes)

DRY_RUN=true ./EC2Shield.sh --region eu-central-1 --instance-id i-0123456789abcdef

## Required IAM Permissions

The Responder user needs these AWS IAM permissions:

* **EC2**

  * `ec2:DescribeInstances`
  * `ec2:ModifyInstanceAttribute`
  * `ec2:CreateSnapshot`
  * `ec2:CreateTags`
  * `ec2:DescribeSecurityGroups`
  * `ec2:CreateSecurityGroup`
  * `ec2:RevokeSecurityGroupEgress`
  * `ec2:ModifyNetworkInterfaceAttribute`

* **Auto Scaling**

  * `autoscaling:DescribeAutoScalingInstances`
  * `autoscaling:DetachInstances`

* **IAM**

  * `iam:CreateRole`
  * `iam:PutRolePolicy`
  * `iam:CreateInstanceProfile`
  * `iam:AddRoleToInstanceProfile`
  * `iam:GetInstanceProfile`

## Output

The script generates reports and artifacts under the chosen output directory (`--out-dir` or default `./ir_artifacts/`):

* **Instance description**: `<instance-id>_describe.json`
* **Summary**: `<instance-id>_summary.tsv`
* **Security Group mapping**: `<instance-id>_pre_sg.json`
* **Containment report**: `<instance-id>_containment_report.txt`
* **IAM policy docs**: `trust.json`, `deny.json`

## Examples

### Simulated test run

DRY_RUN=true ./EC2Shield.sh --region us-east-1 --instance-id i-0abc123def456 --incident-id TEST-IR

### Real isolation

./EC2Shield.sh --region us-east-1 --instance-id i-0abc123def456 --incident-id IR-2025-002 --out-dir ./ir_results

## Project Structure

EC2Shield/
├── EC2Shield.sh
├── README.md
├── LICENSE

