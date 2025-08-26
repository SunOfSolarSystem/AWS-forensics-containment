#!/usr/bin/env bash
set -euo pipefail

# =========================
# AWS IR Containment Script
# =========================

# -------- Config (defaults) --------
REGION="${REGION:-region}"
INSTANCE_ID="${INSTANCE_ID:-i-instanceID}"
INCIDENT_ID="${INCIDENT_ID:-IR-26-08-25}"   
ISOLATION_SG_NAME="${ISOLATION_SG_NAME:-isolation-sg}"
IR_ROLE_NAME="${IR_ROLE_NAME:-IR-DenyAll-Role}"
IR_INSTANCE_PROFILE="${IR_INSTANCE_PROFILE:-IR-DenyAll-InstanceProfile}"
OUT_DIR="${OUT_DIR:-/home/cloudshell-user}"
DRY_RUN_FLAG="${DRY_RUN:-false}"           
SLEEP_AFTER_IAM="${SLEEP_AFTER_IAM:-30}"
MAX_IAM_WAIT="${MAX_IAM_WAIT:-120}"

# -------- Helpers --------
usage() {
  cat <<EOF
Usage: $0 --instance-id <i-...> --region <aws-region> [--incident-id <ID>] [--isolation-sg-name <name>] [--ir-role-name <name>] [--ir-instance-profile <name>] [--out-dir <path>]

Env:
  DRY_RUN=true   -> Append --dry-run to supported EC2 calls (IAM ops are simulated)
EOF
  exit 1
}

log()   { printf "[%s] %s\n" "$(date -u +"%F %T UTC")" "$*" >&2; }
die()   { log "ERROR: $*"; exit 1; }
arn_ok(){ [[ -n "${1:-}" && "$1" != "None" && "$1" != "null" ]]; }

check_dependencies() {
  local missing_tools=()
  command -v aws >/dev/null 2>&1 || missing_tools+=("aws")
  command -v jq  >/dev/null 2>&1 || missing_tools+=("jq")
  if [[ ${#missing_tools[@]} -gt 0 ]]; then
    die "Missing required tools: ${missing_tools[*]}. Please install them first."
  fi
}

validate_aws_access() {
  log "Validating AWS access..."
  aws sts get-caller-identity --region "$REGION" >/dev/null 2>&1 || die "Cannot access AWS. Check credentials/region."
  # Use --max-results for EC2 to avoid CLI paginator differences
  aws ec2 describe-instances --region "$REGION" --max-results 5 >/dev/null 2>&1 || die "No EC2 describe permissions in $REGION"
}

extract_json_value() {
  local json_data="$1"
  local key="$2"
  echo "$json_data" | jq -r ".$key" 2>/dev/null || echo "null"
}

wait_for_iam_propagation() {
  local profile_name="$1"
  local waited=0
  log "Waiting for IAM instance profile propagation..."
  while [[ $waited -lt $MAX_IAM_WAIT ]]; do
    if aws iam get-instance-profile --instance-profile-name "$profile_name" >/dev/null 2>&1; then
      log "IAM instance profile is ready after ${waited}s"
      return 0
    fi
    sleep 5; waited=$((waited + 5))
    if [[ $((waited % 30)) -eq 0 ]]; then
      log "Still waiting for IAM propagation... (${waited}s elapsed)"
    fi
  done
  log "WARNING: IAM propagation took longer than expected (${waited}s)"; return 1
}

# Remove all egress from a security group (supports both rule-ids and ip-permissions)
remove_all_egress_rules() {
  local sg_id="$1"
  log "Removing all egress rules from security group $sg_id"

  local rules_removed=false

  # Try with Security Group Rule IDs
  local rule_ids
  rule_ids=$(aws ec2 describe-security-group-rules --region "$REGION" \
    --filters "Name=group-id,Values=$sg_id" "Name=is-egress,Values=true" \
    --query "SecurityGroupRules[].SecurityGroupRuleId" --output text 2>/dev/null || true)

  if [[ -n "${rule_ids:-}" ]]; then
    for rid in $rule_ids; do
      aws ec2 revoke-security-group-egress --region "$REGION" \
        --group-id "$sg_id" --security-group-rule-ids "$rid" >/dev/null 2>&1 && rules_removed=true || true
    done
  fi

  # Fallback: revoke by IpPermissions (IPv4/IPv6)
  if [[ "$rules_removed" == "false" ]]; then
    aws ec2 revoke-security-group-egress --region "$REGION" \
      --group-id "$sg_id" \
      --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]' >/dev/null 2>&1 && rules_removed=true || true
    aws ec2 revoke-security-group-egress --region "$REGION" \
      --group-id "$sg_id" \
      --ip-permissions 'IpProtocol=-1,Ipv6Ranges=[{CidrIpv6=::/0}]' >/dev/null 2>&1 && rules_removed=true || true
  fi

  # Last resort: pull full IpPermissionsEgress and revoke one-by-one
  if [[ "$rules_removed" == "false" ]]; then
    log "Attempting granular egress rule cleanup for SG $sg_id"
    local sg_details egress_perms
    sg_details=$(aws ec2 describe-security-groups --region "$REGION" --group-ids "$sg_id" --output json 2>/dev/null || echo '{"SecurityGroups":[]}')
    egress_perms=$(echo "$sg_details" | jq -c '.SecurityGroups[0].IpPermissionsEgress[]?' 2>/dev/null || true)
    if [[ -n "$egress_perms" ]]; then
      while IFS= read -r perm; do
        [[ -z "$perm" ]] && continue
        aws ec2 revoke-security-group-egress --region "$REGION" \
          --group-id "$sg_id" --ip-permissions "$perm" >/dev/null 2>&1 || true
      done <<< "$egress_perms"
    fi
  fi
}

# Attach isolation SG to all ENIs (validated)
validate_and_process_enis() {
  local eni_ids="$1"
  local isolation_sg="$2"
  local dry_run="$3"

  if [[ -z "$eni_ids" ]]; then
    log "WARNING: No ENI IDs found for instance"
    return 1
  fi

  local eni_count=0
  for eni in $eni_ids; do
    [[ -z "$eni" ]] && continue
    eni_count=$((eni_count + 1))
    if [[ -n "$dry_run" ]]; then
      log "DRY RUN: Would set isolation SG on ENI $eni"
    else
      aws ec2 modify-network-interface-attribute --region "$REGION" \
        --network-interface-id "$eni" --groups "$isolation_sg" >/dev/null 2>&1 \
        && log "Successfully attached isolation SG to ENI $eni" \
        || log "WARNING: Failed to attach isolation SG to ENI $eni"
    fi
  done
  log "Processed $eni_count network interfaces"
  return 0
}

# -------- Parse args --------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --region) REGION="$2"; shift 2;;
    --instance-id) INSTANCE_ID="$2"; shift 2;;
    --incident-id) INCIDENT_ID="$2"; shift 2;;
    --isolation-sg-name) ISOLATION_SG_NAME="$2"; shift 2;;
    --ir-role-name) IR_ROLE_NAME="$2"; shift 2;;
    --ir-instance-profile) IR_INSTANCE_PROFILE="$2"; shift 2;;
    --out-dir) OUT_DIR="$2"; shift 2;;
    -h|--help) usage;;
    *) die "Unknown flag: $1";;
  esac
done

[[ -n "$REGION" ]] || usage
[[ -n "$INSTANCE_ID" ]] || usage

# -------- Pre-flight --------
check_dependencies
validate_aws_access

DRY=""
IAM_DRY=""  # IAM doesn't support --dry-run; we'll simulate
if [[ "$DRY_RUN_FLAG" == "true" ]]; then
  DRY="--dry-run"
  IAM_DRY="DRY_RUN"
  log "DRY RUN ENABLED - EC2 ops will use --dry-run. IAM ops will be simulated."
fi

mkdir -p "$OUT_DIR"

log "Starting IR containment for instance: $INSTANCE_ID (region: $REGION, incident: $INCIDENT_ID)"

# Describe instance (force JSON)
DESC_JSON="$OUT_DIR/${INSTANCE_ID}_describe.json"
if ! aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" --output json > "$DESC_JSON"; then
  die "Failed to describe instance $INSTANCE_ID. Check if it exists and permissions."
fi

INSTANCE_COUNT=$(jq '.Reservations | length' "$DESC_JSON")
[[ "$INSTANCE_COUNT" -gt 0 ]] || die "Instance $INSTANCE_ID not found in region $REGION"

# Extract attributes with defaults
STATE=$(jq -r '.Reservations[0].Instances[0].State.Name // "unknown"' "$DESC_JSON")
VPC_ID=$(jq -r '.Reservations[0].Instances[0].VpcId // "None"' "$DESC_JSON")
SUBNET_ID=$(jq -r '.Reservations[0].Instances[0].SubnetId // "None"' "$DESC_JSON")
PRIVATE_IP=$(jq -r '.Reservations[0].Instances[0].PrivateIpAddress // "None"' "$DESC_JSON")
PUBLIC_IP=$(jq -r '.Reservations[0].Instances[0].PublicIpAddress // "None"' "$DESC_JSON")
AMI_ID=$(jq -r '.Reservations[0].Instances[0].ImageId // "None"' "$DESC_JSON")
IAM_PROFILE_ARN=$(jq -r '.Reservations[0].Instances[0].IamInstanceProfile.Arn // "None"' "$DESC_JSON")
ENI_IDS=$(jq -r '.Reservations[0].Instances[0].NetworkInterfaces[]?.NetworkInterfaceId // empty' "$DESC_JSON" | tr '\n' ' ')

log "Instance state: $STATE | VPC: $VPC_ID | Subnet: $SUBNET_ID | PrivateIP: $PRIVATE_IP | PublicIP: $PUBLIC_IP | AMI: $AMI_ID | IAMProfile: $IAM_PROFILE_ARN"
log "Network interfaces: ${ENI_IDS:-"None found"}"

# Validate state & VPC
case "$STATE" in
  running|stopped|stopping) log "Instance state ($STATE) is suitable for containment.";;
  terminated|terminating)   die "Cannot contain terminated/terminating instance";;
  unknown)                  die "Could not determine instance state";;
  *)                        log "WARNING: Unusual instance state ($STATE). Proceeding with caution.";;
esac
if [[ "$VPC_ID" == "None" || "$VPC_ID" == "null" || -z "$VPC_ID" ]]; then
  die "Instance $INSTANCE_ID is not in a VPC (or VPC not found). Isolation SG requires VPC."
fi

# Save pre-isolation SG/ENI mapping
PRE_SG_FILE="$OUT_DIR/${INSTANCE_ID}_pre_sg.json"
if ! jq -r '.Reservations[0].Instances[0].NetworkInterfaces[]? | {NetworkInterfaceId, Groups: [.Groups[]?.GroupId]}' "$DESC_JSON" > "$PRE_SG_FILE" 2>/dev/null; then
  log "WARNING: Could not save pre-isolation SG mapping"
  echo "[]" > "$PRE_SG_FILE"
fi
log "Saved pre-isolation SG mapping: $PRE_SG_FILE"

# -------- 1) Detach from Auto Scaling Group --------
log "Checking Auto Scaling membership..."
ASG_DATA=$(aws autoscaling describe-auto-scaling-instances --region "$REGION" --instance-ids "$INSTANCE_ID" --output json 2>/dev/null || echo '{"AutoScalingInstances":[]}')
ASG_NAME=$(echo "$ASG_DATA" | jq -r '.AutoScalingInstances[0].AutoScalingGroupName // "None"')

if [[ -n "$ASG_NAME" && "$ASG_NAME" != "None" ]]; then
  log "Instance is in ASG: $ASG_NAME -> detaching (decrement desired capacity)"
  if [[ -n "$DRY" ]]; then
    log "DRY RUN: Would detach instance from ASG $ASG_NAME"
  else
    aws autoscaling detach-instances \
      --region "$REGION" \
      --instance-ids "$INSTANCE_ID" \
      --auto-scaling-group-name "$ASG_NAME" \
      --should-decrement-desired-capacity >/dev/null 2>&1 \
      && log "Successfully detached instance from ASG $ASG_NAME" \
      || log "WARNING: Failed to detach from ASG. Continuing..."
  fi
else
  log "Instance is NOT in an Auto Scaling Group."
fi

# -------- 2) Snapshot all attached EBS volumes --------
log "Creating snapshots for attached EBS volumes..."
EBS_VOLUMES=$(jq -r '.Reservations[0].Instances[0].BlockDeviceMappings[]? | select(.Ebs != null) | .Ebs.VolumeId' "$DESC_JSON" | tr '\n' ' ' || echo "")
SNAP_OK=0
SNAP_TOTAL=0

if [[ -z "$EBS_VOLUMES" || "$EBS_VOLUMES" == " " ]]; then
  log "No EBS volumes found on instance."
else
  for VOL in $EBS_VOLUMES; do
    [[ -z "$VOL" ]] && continue
    SNAP_TOTAL=$((SNAP_TOTAL + 1))
    DESC_TXT="IR $INCIDENT_ID snapshot of $VOL from $INSTANCE_ID"
    log "Creating snapshot for volume $VOL"
    if [[ -n "$DRY" ]]; then
      log "DRY RUN: Would create snapshot for volume $VOL"
      SNAP_OK=$((SNAP_OK + 1))
      continue
    fi
    SNAP_JSON=$(aws ec2 create-snapshot --region "$REGION" --volume-id "$VOL" --description "$DESC_TXT" --output json 2>/dev/null || true)
    if [[ -n "${SNAP_JSON:-}" ]]; then
      SNAP_ID=$(extract_json_value "$SNAP_JSON" "SnapshotId")
      if [[ "$SNAP_ID" != "null" && -n "$SNAP_ID" ]]; then
        SNAP_OK=$((SNAP_OK + 1))
        log "Created snapshot $SNAP_ID for volume $VOL"
        aws ec2 create-tags --region "$REGION" --resources "$SNAP_ID" \
          --tags "Key=IncidentId,Value=$INCIDENT_ID" "Key=SourceInstance,Value=$INSTANCE_ID" "Key=SourceVolume,Value=$VOL" >/dev/null 2>&1 \
          && log "Successfully tagged snapshot $SNAP_ID" \
          || log "WARNING: Failed to tag snapshot $SNAP_ID"
      else
        log "WARNING: Failed to extract snapshot ID from response for volume $VOL"
      fi
    else
      log "WARNING: Failed to create snapshot for volume $VOL"
    fi
  done
fi
log "Snapshot summary: $SNAP_OK/$SNAP_TOTAL volumes successfully snapshotted"

# -------- 3) Save metadata --------
SUMMARY_TSV="$OUT_DIR/${INSTANCE_ID}_summary.tsv"
echo -e "InstanceId\tState\tRegion\tVPC\tSubnet\tPrivateIP\tPublicIP\tAMI\tIAMProfileArn\tIncidentId\tTimestamp" > "$SUMMARY_TSV"
echo -e "$INSTANCE_ID\t$STATE\t$REGION\t$VPC_ID\t$SUBNET_ID\t$PRIVATE_IP\t$PUBLIC_IP\t$AMI_ID\t$IAM_PROFILE_ARN\t$INCIDENT_ID\t$(date -u +"%F %T UTC")" >> "$SUMMARY_TSV"
log "Wrote metadata to: $DESC_JSON and $SUMMARY_TSV"

# -------- 4) Isolation Security Group --------
log "Ensuring isolation Security Group exists (name: $ISOLATION_SG_NAME) in VPC $VPC_ID"
ISO_SG_DATA=$(aws ec2 describe-security-groups --region "$REGION" \
  --filters "Name=group-name,Values=$ISOLATION_SG_NAME" "Name=vpc-id,Values=$VPC_ID" --output json 2>/dev/null || echo '{"SecurityGroups":[]}')
ISO_SG_ID=$(echo "$ISO_SG_DATA" | jq -r '.SecurityGroups[0].GroupId // "None"')

if [[ "$ISO_SG_ID" == "None" ]]; then
  log "Creating isolation SG..."
  if [[ -n "$DRY" ]]; then
    log "DRY RUN: Would create security group $ISOLATION_SG_NAME"
    ISO_SG_ID="sg-dryrun123456789"
  else
    CREATE_OUT=$(aws ec2 create-security-group --region "$REGION" \
      --group-name "$ISOLATION_SG_NAME" --description "IR isolation SG (no ingress/egress)" --vpc-id "$VPC_ID" --output json 2>/dev/null || true)
    if [[ -n "${CREATE_OUT:-}" ]]; then
      ISO_SG_ID=$(extract_json_value "$CREATE_OUT" "GroupId")
      if [[ "$ISO_SG_ID" != "null" && -n "$ISO_SG_ID" ]]; then
        log "Created isolation security group: $ISO_SG_ID"
        remove_all_egress_rules "$ISO_SG_ID"
        aws ec2 create-tags --region "$REGION" --resources "$ISO_SG_ID" \
          --tags "Key=Name,Value=$ISOLATION_SG_NAME" "Key=IncidentId,Value=$INCIDENT_ID" "Key=Purpose,Value=IR-Isolation" >/dev/null 2>&1 || true
      else
        die "Failed to obtain created SG ID"
      fi
    else
      die "Failed to create security group"
    fi
  fi
else
  log "Using existing isolation SG: $ISO_SG_ID"
  if [[ -z "$DRY" ]]; then
    log "Ensuring no egress rules on existing isolation SG..."
    remove_all_egress_rules "$ISO_SG_ID"
  fi
fi

# Attach isolation SG to ALL ENIs
log "Attaching isolation SG to ALL network interfaces..."
validate_and_process_enis "$ENI_IDS" "$ISO_SG_ID" "$DRY"

# Backup: also try the instance-level call (primary ENI)
if [[ -n "$DRY" ]]; then
  log "DRY RUN: Would also call modify-instance-attribute to replace SGs"
else
  aws ec2 modify-instance-attribute --region "$REGION" \
    --instance-id "$INSTANCE_ID" --groups "$ISO_SG_ID" >/dev/null 2>&1 \
    && log "Successfully applied isolation SG at instance level" \
    || log "WARNING: Instance-level SG replace may not apply when ENI-level already set (safe to ignore)"
fi

# -------- 5) IAM Role & Instance Profile (Deny-All) --------
log "Managing IR Deny-All IAM role & instance profile..."
if [[ "$IAM_DRY" == "DRY_RUN" ]]; then
  log "DRY RUN: Would create/manage IAM role $IR_ROLE_NAME and instance profile $IR_INSTANCE_PROFILE"
else
  PROFILE_EXISTS=false
  aws iam get-instance-profile --instance-profile-name "$IR_INSTANCE_PROFILE" >/dev/null 2>&1 && PROFILE_EXISTS=true

  if [[ "$PROFILE_EXISTS" == "false" ]]; then
    log "Creating IAM role $IR_ROLE_NAME..."
    TRUST_DOC='{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole"
      }]
    }'
    echo "$TRUST_DOC" > "$OUT_DIR/trust.json"

    aws iam create-role --role-name "$IR_ROLE_NAME" \
      --assume-role-policy-document "file://$OUT_DIR/trust.json" \
      --description "IR containment role - denies all actions" >/dev/null 2>&1 || log "WARNING: Failed to create IAM role (may already exist)"

    log "Attaching Deny-All policy to role..."
    DENY_DOC='{
      "Version": "2012-10-17",
      "Statement": [{"Effect": "Deny","Action": "*","Resource": "*"}]
    }'
    echo "$DENY_DOC" > "$OUT_DIR/deny.json"
    aws iam put-role-policy --role-name "$IR_ROLE_NAME" \
      --policy-name "DenyAllInline" \
      --policy-document "file://$OUT_DIR/deny.json" >/dev/null 2>&1 || log "WARNING: Failed to apply Deny-All policy"

    log "Creating instance profile $IR_INSTANCE_PROFILE..."
    aws iam create-instance-profile --instance-profile-name "$IR_INSTANCE_PROFILE" >/dev/null 2>&1 || log "WARNING: Failed to create instance profile"
    aws iam add-role-to-instance-profile --instance-profile-name "$IR_INSTANCE_PROFILE" --role-name "$IR_ROLE_NAME" >/dev/null 2>&1 || log "WARNING: Failed to add role to instance profile"

    wait_for_iam_propagation "$IR_INSTANCE_PROFILE" || log "WARNING: IAM propagation may be incomplete"
    # Sanity check: ensure role is in profile
    aws iam get-instance-profile --instance-profile-name "$IR_INSTANCE_PROFILE" \
      --query "InstanceProfile.Roles[?RoleName=='$IR_ROLE_NAME'] | length(@)" --output text >/dev/null 2>&1 || true
  else
    log "Instance profile $IR_INSTANCE_PROFILE already exists"
  fi

  # Associate/Replace instance profile on the instance
  log "Managing IAM instance profile association..."
  ASSOC_DATA=$(aws ec2 describe-iam-instance-profile-associations --region "$REGION" \
    --filters "Name=instance-id,Values=$INSTANCE_ID" --output json 2>/dev/null || echo '{"IamInstanceProfileAssociations":[]}')
  ASSOC_ID=$(echo "$ASSOC_DATA" | jq -r '.IamInstanceProfileAssociations[0].AssociationId // "None"')

  if [[ "$ASSOC_ID" != "None" ]]; then
    log "Replacing existing IAM instance profile association ($ASSOC_ID)"
    aws ec2 replace-iam-instance-profile-association --region "$REGION" \
      --association-id "$ASSOC_ID" \
      --iam-instance-profile "Name=$IR_INSTANCE_PROFILE" >/dev/null 2>&1 || log "WARNING: Failed to replace instance profile association"
  else
    log "Creating new IAM instance profile association"
    aws ec2 associate-iam-instance-profile --region "$REGION" \
      --instance-id "$INSTANCE_ID" \
      --iam-instance-profile "Name=$IR_INSTANCE_PROFILE" >/dev/null 2>&1 || log "WARNING: Failed to associate instance profile"
  fi
fi

# -------- Final tagging --------
if [[ -z "$DRY" ]]; then
  log "Tagging instance with incident information..."
  aws ec2 create-tags --region "$REGION" --resources "$INSTANCE_ID" \
    --tags "Key=IncidentId,Value=$INCIDENT_ID" \
           "Key=Isolation,Value=Applied" \
           "Key=IsolationTimestamp,Value=$(date -u +"%F_%T_UTC")" \
           "Key=IsolationScript,Value=aws-ir-containment" >/dev/null 2>&1 || log "WARNING: Failed to tag instance"
fi

# -------- Final Report --------
REPORT_FILE="$OUT_DIR/${INSTANCE_ID}_containment_report.txt"
cat > "$REPORT_FILE" << EOF
AWS EC2 Instance Containment Report
===================================

Instance ID: $INSTANCE_ID
Region: $REGION
Incident ID: $INCIDENT_ID
Containment Time: $(date -u +"%F %T UTC")
Script Version: Hardened & Fixed

Pre-Containment State:
- Instance State: $STATE
- VPC ID: $VPC_ID
- Subnet ID: $SUBNET_ID
- Private IP: $PRIVATE_IP
- Public IP: $PUBLIC_IP
- AMI ID: $AMI_ID
- Original IAM Profile: $IAM_PROFILE_ARN
- Network Interfaces: $(echo "$ENI_IDS" | wc -w) ENIs found

Containment Actions Applied:
- Auto Scaling Group: $([ "$ASG_NAME" != "None" ] && echo "Detached from $ASG_NAME" || echo "Not applicable")
- EBS Snapshots: $SNAP_OK/$SNAP_TOTAL snapshots created successfully
- Security Groups: Replaced with isolation SG ($ISO_SG_ID) on ALL ENIs
- IAM Profile: Applied/Ensured Deny-All profile ($IR_INSTANCE_PROFILE)
- Instance Tagging: Applied incident tracking tags

Files Generated:
- Instance Description: $DESC_JSON
- Pre-Isolation SG Map: $PRE_SG_FILE
- Summary: $SUMMARY_TSV
- This Report: $REPORT_FILE
- IAM Policy Files: $OUT_DIR/trust.json, $OUT_DIR/deny.json

$([ "$DRY_RUN_FLAG" == "true" ] && echo "NOTE: This was a DRY RUN - no actual changes were made to AWS resources")

Status Summary:
$([ "$DRY_RUN_FLAG" == "true" ] && echo "- DRY RUN: All operations were simulated" || echo "- LIVE RUN: All containment actions were executed")
- ASG Detachment: $([ "$ASG_NAME" != "None" ] && echo "SUCCESS" || echo "N/A")
- Snapshots: $SNAP_OK/$SNAP_TOTAL volumes
- Network Isolation: Applied to $(echo "$ENI_IDS" | wc -w) network interfaces
- IAM Containment: $([ "$IAM_DRY" == "DRY_RUN" ] && echo "SIMULATED" || echo "APPLIED")

Next Steps:
1. Verify network isolation is complete
2. Monitor instance for any remaining suspicious activity
3. Begin forensic analysis using created snapshots
4. Review and analyze logs from before containment
5. Consider additional monitoring or shutdown if needed

IMPORTANT: This instance is now isolated and should have minimal AWS permissions.
Any legitimate access will need to be restored manually after investigation.
EOF

log "IR containment completed for $INSTANCE_ID."
log "Full report: $REPORT_FILE"
log "Summary artifacts: $DESC_JSON, $SUMMARY_TSV, $PRE_SG_FILE"

if [[ "$DRY_RUN_FLAG" == "true" ]]; then
  log "DRY RUN completed - no actual changes were made to AWS resources"
else
  log "LIVE containment completed - instance is now isolated"
  log "WARNING: Instance has been isolated and will have limited functionality"
fi

# -------- Final validation (non-dry) --------
if [[ -z "$DRY" ]]; then
  log "Performing final validation..."
  CURRENT_SG=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
    --query "Reservations[0].Instances[0].SecurityGroups[0].GroupId" --output text 2>/dev/null || echo "unknown")
  if [[ "$CURRENT_SG" == "$ISO_SG_ID" ]]; then
    log "✓ Validation: Isolation security group successfully applied (primary ENI)"
  else
    log "✗ Validation: Security group on primary ENI differs (current: $CURRENT_SG, expected: $ISO_SG_ID)"
  fi

  CURRENT_PROFILE=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
    --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" --output text 2>/dev/null || echo "None")
  if [[ "$CURRENT_PROFILE" != "None" && "$CURRENT_PROFILE" == *"$IR_INSTANCE_PROFILE"* ]]; then
    log "✓ Validation: Deny-All IAM profile successfully applied"
  else
    log "✗ Validation: IAM profile may not be properly applied (current: $CURRENT_PROFILE)"
  fi
fi

log "Containment script execution completed at $(date -u +"%F %T UTC")"
