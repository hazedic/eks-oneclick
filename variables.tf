variable "KeyName" {
  description = "Name of an existing EC2 KeyPair for SSH access"
  type        = string
}

variable "LatestAmiId" {
  description = "SSM parameter name for the latest Amazon Linux 2 AMI"
  type        = string
  default     = "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
}

variable "ClusterBaseName" {
  description = "Cluster base name"
  type        = string
  default     = "myeks"
}

variable "KubernetesVersion" {
  description = "Kubernetes version (e.g., 1.26)"
  type        = string
  default     = "1.26"
}

variable "WorkerNodeInstanceType" {
  description = "EC2 Instance Type for Worker Nodes"
  type        = string
  default     = "t3.micro"
}

variable "WorkerNodeCount" {
  description = "Number of Worker Nodes"
  type        = number
  default     = 3
}

variable "WorkerNodeVolumesize" {
  description = "Worker Node volume size (GiB)"
  type        = number
  default     = 30
}

variable "TargetRegion" {
  description = "AWS Region"
  type        = string
  default     = "ap-northeast-2"
}

variable "AvailabilityZone1" {
  description = "Availability Zone 1"
  type        = string
  default     = "ap-northeast-2a"
}

variable "AvailabilityZone2" {
  description = "Availability Zone 2"
  type        = string
  default     = "ap-northeast-2b"
}

variable "AvailabilityZone3" {
  description = "Availability Zone 3"
  type        = string
  default     = "ap-northeast-2c"
}

variable "VpcBlock" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "192.168.0.0/16"
}

variable "PublicSubnet1Block" {
  description = "CIDR block for Public Subnet 1"
  type        = string
  default     = "192.168.1.0/24"
}

variable "PublicSubnet2Block" {
  description = "CIDR block for Public Subnet 2"
  type        = string
  default     = "192.168.2.0/24"
}

variable "PublicSubnet3Block" {
  description = "CIDR block for Public Subnet 3"
  type        = string
  default     = "192.168.3.0/24"
}

variable "BastionInstanceType" {
  description = "EC2 instance type for the bastion host"
  type        = string
  default     = "t3.micro"
}
