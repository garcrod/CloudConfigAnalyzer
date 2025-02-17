import json
import sys
from typing import Dict, List
from dataclasses import dataclass

@dataclass
class SecurityIssue:
    severity: str
    message: str
    resource: str
    category: str

class CloudSecurityScanner:
    def __init__(self, json_content: str):
        self.config = self._load_config(json_content)
        self.issues: List[SecurityIssue] = []

    def _load_config(self, json_content: str) -> Dict:
        try:
            return json.loads(json_content)
        except json.JSONDecodeError as e:
            print(f"Error loading config: {e}")
            sys.exit(1)

    def scan_gcp_config(self):
        # Check for GCP service configuration
        if 'apiVersion' in self.config:
            self._check_gcp_mfa()
            self._check_gcp_encryption()
            self._check_gcp_containers()
            self._check_gcp_secrets()
            self._check_gcp_openstorage()
            self._check_gcp_ports()

    def scan_azure_config(self):
        # Check for Azure resources
        if 'resources' in self.config:
            for resource in self.config['resources']:
                self._check_azure_mfa(resource)
                self._check_azure_encryption(resource)
                self._check_azure_containers(resource)
                self._check_azure_secrets(resource)
                self._check_azure_openstorage(resource)
                self._check_azure_ports(resource)
    
    def scan_aws_config(self):
        # Check for AWS resources
        if 'IAM' or 'S3' or 'EC2' in self.config:
            self._check_aws_mfa()
            self._check_aws_encryption()
            self._check_aws_containers()
            self._check_aws_secrets()
            self._check_aws_openstorage()
            self._check_aws_ports()

    def _check_aws_mfa(self):
        # Check IAM users for MFA
        iam_users = self.config.get('IAM', {}).get('Users', [])
        for user in iam_users:
            if not user.get('MFAEnabled', False):
                self.issues.append(SecurityIssue(
                    severity="HIGH",
                    message="MFA is not enabled for IAM user",
                    resource=f"User {user.get('UserName', 'unknown')}",
                    category="Authentication"
                ))

    def _check_aws_encryption(self):
        # Check S3 buckets encryption
        s3_buckets = self.config.get('S3', {}).get('Buckets', [])
        for bucket in s3_buckets:
            if not bucket.get('Encryption', False):
                self.issues.append(SecurityIssue(
                    severity="HIGH",
                    message="S3 bucket is not encrypted",
                    resource=f"Bucket {bucket.get('Name', 'unknown')}",
                    category="Encryption"
                ))

    def _check_aws_containers(self):
        # Check ECS task definitions and EKS pods for privileged containers
        containers = self.config.get('ECS', {}).get('TaskDefinitions', []) + self.config.get('EKS', {}).get('Pods', [])
        for container in containers:
            if container.get('privileged', False):
                self.issues.append(SecurityIssue(
                    severity="HIGH",
                    message="Container is running with privileged mode enabled",
                    resource=f"Container {container.get('name', 'unknown')}",
                    category="Privilege"
                ))
            
            # Check for root user
            if container.get('user') == 'root' or container.get('uid') == 0:
                self.issues.append(SecurityIssue(
                    severity="HIGH",
                    message="Container is running as root user",
                    resource=f"Container {container.get('name', 'unknown')}",
                    category="Privilege"
                ))

    def _check_aws_ports(self):
        # Check EC2 security groups for open ports
        security_groups = self.config.get('EC2', {}).get('SecurityGroups', [])
        sensitive_ports = {80, 22, 3389, 5985, 5986}
        for sg in security_groups:
            inbound_rules = sg.get('InboundRules', [])
            for rule in inbound_rules:
                if rule.get('CidrIp') == '0.0.0.0/0':
                    port = rule.get('FromPort')
                    if port in sensitive_ports:
                        severity = "HIGH"
                        message = f"Sensible port {port} is open"
                    else:
                        severity = "LOW"
                        message = f"Port {port} is open"
                    self.issues.append(SecurityIssue(
                        severity=severity,
                        message=message,
                        resource=f"Security Group {sg.get('GroupName', 'unknown')}",
                        category="Network"
                    ))

    def _check_aws_secrets(self):
        # Check for exposed passwords in configuration
        if any('password' or 'secret' or 'key' or 'token' or'credential' in key for key in self.config.keys()):
            self.issues.append(SecurityIssue(
                severity="HIGH", 
                message="Password found in configuration",
                resource="AWS Configuration",
                category="Secrets"
            ))
    
    def _check_aws_openstorage(self):
        # Check S3 buckets for public access
        s3_buckets = self.config.get('S3', {}).get('Buckets', [])
        for bucket in s3_buckets:
            if bucket.get('PublicAccessBlock', {}).get('BlockPublicAcls') is False or \
               bucket.get('PublicAccessBlock', {}).get('BlockPublicPolicy') is False or \
               bucket.get('PublicAccessBlock', {}).get('IgnorePublicAcls') is False or \
               bucket.get('PublicAccessBlock', {}).get('RestrictPublicBuckets') is False:
                self.issues.append(SecurityIssue(
                    severity="HIGH",
                    message="S3 bucket has public access enabled",
                    resource=f"Bucket {bucket.get('Name', 'unknown')}",
                    category="Access Control"
                ))

    def _check_gcp_mfa(self):
        # Check MFA for Knative services
        mfa_enabled = self.config.get('metadata', {}).get('annotations', {}).get('security.knative.dev/mfaEnabled')
        if mfa_enabled == "false":
            self.issues.append(SecurityIssue(
                severity="HIGH",
                message="MFA is not enabled for the Knative service",
                resource="GCP Knative Service",
                category="Authentication"
            ))

        # Check MFA for IAM users
        iam_users = self.config.get('iam', {}).get('users', [])
        for user in iam_users:
            if not user.get('mfaEnabled', False):
                self.issues.append(SecurityIssue(
                    severity="HIGH",
                    message="MFA is not enabled for IAM user",
                    resource=f"IAM User {user.get('name', 'unknown')}",
                    category="Authentication"
                ))

        # Check MFA for other services (e.g., Cloud Functions)
        functions = self.config.get('functions', [])
        for function in functions:
            if not function.get('mfaEnabled', False):
                self.issues.append(SecurityIssue(
                    severity="HIGH",
                    message="MFA is not enabled for Cloud Function",
                    resource=f"Cloud Function {function.get('name', 'unknown')}",
                    category="Authentication"
                ))

    def _check_gcp_encryption(self):
        # Check encryption settings in containers and volumes
        template_spec = self.config.get('spec', {}).get('template', {}).get('spec', {})
        
        # Check container image encryption
        containers = template_spec.get('containers', [])
        for container in containers:
            if not container.get('imageEncryption', {}).get('enabled', False):
                self.issues.append(SecurityIssue(
                    severity="HIGH",
                    message="Container image encryption not enabled",
                    resource=f"Container {container.get('name', 'unknown')}",
                    category="Encryption"
                ))
        
        # Check volume encryption
        volumes = template_spec.get('volumes', [])
        for volume in volumes:
            if volume.get('gcePersistentDisk') and not volume.get('encrypted', True):
                self.issues.append(SecurityIssue(
                    severity="HIGH",
                    message="Volume encryption not enabled",
                    resource=f"Volume {volume.get('name', 'unknown')}",
                    category="Encryption"
                ))

    def _check_gcp_containers(self):
        containers = self.config.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
        for container in containers:
            # Check for root user
            security_context = container.get('securityContext', {})
            if security_context.get('runAsUser') == 0:
                self.issues.append(SecurityIssue(
                    severity="HIGH",
                    message="Container is running as root user",
                    resource=f"Container {container.get('name', 'unknown')}",
                    category="Privilege"
                ))

            # Check for latest tag
            if ':latest' in container.get('image', ''):
                self.issues.append(SecurityIssue(
                    severity="MEDIUM",
                    message="Container using 'latest' tag",
                    resource=f"Container {container.get('name', 'unknown')}",
                    category="Version Control"
                ))

    def _check_gcp_secrets(self):
                # Check environment variables in containers for potential secrets
                containers = self.config.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
                for container in containers:
                    # Check environment variables
                    env_vars = container.get('env', [])
                    for env in env_vars:
                        name = env.get('name', '').lower()
                        if any(secret_word in name for secret_word in ['secret', 'password', 'key', 'token', 'credential']):
                            self.issues.append(SecurityIssue(
                                severity="HIGH",
                                message=f"Potential secret found in environment variable: {env.get('name')}",
                                resource=f"Container {container.get('name', 'unknown')}",
                                category="Secrets"
                            ))
                    
                    # Check mounted secrets
                    volume_mounts = container.get('volumeMounts', [])
                    for mount in volume_mounts:
                        if mount.get('name', '').lower().startswith('secret-'):
                            self.issues.append(SecurityIssue(
                                severity="MEDIUM",
                                message=f"Secret volume mounted: {mount.get('name')}",
                                resource=f"Container {container.get('name', 'unknown')}",
                                category="Secrets"
                            ))         

    def _check_gcp_openstorage(self):
        storage_config = self.config.get('spec', {}).get('template', {}).get('spec', {}).get('volumes', [])
        
        for volume in storage_config:
            # Check for public access settings
            if volume.get('gcePersistentDisk', {}).get('readOnly') is False:
                self.issues.append(SecurityIssue(
                    severity="HIGH",
                    message="GCP storage volume has write access enabled",
                    resource=f"Volume {volume.get('name', 'unknown')}",
                    category="Storage"
                ))
            
            # Check for public bucket access
            if volume.get('gcsBucket', {}).get('publicAccess') is True:
                self.issues.append(SecurityIssue(
                    severity="HIGH",
                    message="GCS bucket has public access enabled", 
                    resource=f"Volume {volume.get('name', 'unknown')}",
                    category="Access Control"
                ))
            
            # Check for sensitive data in temporary storage
            if volume.get('emptyDir'):
                self.issues.append(SecurityIssue(
                    severity="MEDIUM",
                    message="Using emptyDir volume which is temporary and less secure",
                    resource=f"Volume {volume.get('name', 'unknown')}",
                    category="Storage"
                ))

    def _check_gcp_ports(self):
        containers = self.config.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
        sensitive_ports = {80, 22, 3389, 5985, 5986}
        
        for container in containers:
            # Check container ports
            ports = container.get('ports', [])
            for port in ports:
                port_number = port.get('containerPort')
                if port_number:
                    if port_number in sensitive_ports:
                        severity = "HIGH"
                        message = f"Sensible port {port_number} is open"
                    else:
                        severity = "LOW"
                        message = f"Port {port_number} is open"
                    self.issues.append(SecurityIssue(
                        severity=severity,
                        message=f"Container exposing port {port_number}",
                        resource=f"Container {container.get('name', 'unknown')}",
                        category="Network"
                    ))

    def _check_azure_mfa(self, resource):
        if not resource.get('mfa_enabled', False):
            self.issues.append(SecurityIssue(
                severity="HIGH",
                message="MFA is not enabled",
                resource=f"Azure {resource['type']} - {resource['name']}",
                category="Authentication"
            ))

    def _check_azure_encryption(self, resource):
        if not resource.get('encryption', True):
            self.issues.append(SecurityIssue(
                severity="HIGH",
                message="Resource is not encrypted",
                resource=f"Azure {resource['type']} - {resource['name']}",
                category="Encryption"
            ))

    def _check_azure_containers(self, resource):
        containers = resource.get('containers', [])
        for container in containers:
            # Check for privileged containers
            if container.get('privileged', False):
                self.issues.append(SecurityIssue(
                    severity="HIGH",
                    message="Container running in privileged mode",
                    resource=f"Azure {resource['type']} - {resource['name']}",
                    category="Privilege"
                ))
            
            # Check for root user
            if container.get('run_as_user') == 0:
                self.issues.append(SecurityIssue(
                    severity="HIGH", 
                    message="Container running as root user",
                    resource=f"Azure {resource['type']} - {resource['name']}",
                    category="Privilege"
                ))

    def _check_azure_ports(self, resource):
        sensitive_ports = {80, 22, 3389, 5985, 5986}
        open_ports = resource.get('open_ports', [])
        for port in open_ports:
            if port in sensitive_ports:
                severity = "HIGH"
                message = f"Sensible port {port} is open"
            else:
                severity = "LOW"
                message = f"Port {port} is open"
            self.issues.append(SecurityIssue(
                severity=severity,
                message=message,
                resource=f"Azure {resource['type']} - {resource['name']}",
                category="Network"
            ))

    def _check_azure_secrets(self, resource):
        if 'password' or 'secret' or 'key' or 'token' or'credential' in resource:
            self.issues.append(SecurityIssue(
                severity="HIGH",
                message="Password exposed in configuration",
                resource=f"Azure {resource['type']} - {resource['name']}",
                category="Secrets"
            ))

    def _check_azure_openstorage(self, resource):
        # Check storage account public access
        if resource.get('type') == 'Microsoft.Storage/storageAccounts':
            if resource.get('properties', {}).get('allowBlobPublicAccess', False):
                self.issues.append(SecurityIssue(
                    severity="HIGH",
                    message="Storage account allows public blob access",
                    resource=f"Azure {resource['type']} - {resource['name']}",
                    category="Access Control"
                ))
            
            if resource.get('properties', {}).get('allowSharedKeyAccess', False):
                self.issues.append(SecurityIssue(
                    severity="MEDIUM",
                    message="Storage account allows shared key access",
                    resource=f"Azure {resource['type']} - {resource['name']}",
                    category="Access Control"
                ))
            
            # Check network access rules
            if resource.get('properties', {}).get('networkAcls', {}).get('defaultAction') == 'Allow':
                self.issues.append(SecurityIssue(
                    severity="HIGH",
                    message="Storage account network rules allow access by default",
                    resource=f"Azure {resource['type']} - {resource['name']}",
                    category="Network"
                ))

    def scan(self):
        # Detect config type and run appropriate checks
        if 'apiVersion' in self.config:
            self.scan_gcp_config()
        elif 'resources' in self.config:
            self.scan_azure_config()
        elif 'IAM' or 'S3' or 'EC2' in self.config:
            self.scan_aws_config()
        return self.issues

def scan_config(json_content: str) -> List[SecurityIssue]:
    scanner = CloudSecurityScanner(json_content)
    return scanner.scan()