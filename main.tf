##############################
# Provider
##############################
provider "aws" {
  region = var.TargetRegion
}

##############################
# Data: Latest Amazon Linux 2 AMI
##############################
data "aws_ssm_parameter" "latest_ami" {
  name = var.LatestAmiId
}

##############################
# VPC & Subnets
##############################
resource "aws_vpc" "eks_vpc" {
  cidr_block           = var.VpcBlock
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.ClusterBaseName}-VPC"
  }
}

resource "aws_subnet" "public_subnet1" {
  vpc_id                  = aws_vpc.eks_vpc.id
  cidr_block              = var.PublicSubnet1Block
  availability_zone       = var.AvailabilityZone1
  map_public_ip_on_launch = true

  tags = {
    Name                                       = "${var.ClusterBaseName}-PublicSubnet1"
    "kubernetes.io/role/elb"                   = "1"
    "kubernetes.io/cluster/${var.ClusterBaseName}" = "shared"
  }
}

resource "aws_subnet" "public_subnet2" {
  vpc_id                  = aws_vpc.eks_vpc.id
  cidr_block              = var.PublicSubnet2Block
  availability_zone       = var.AvailabilityZone2
  map_public_ip_on_launch = true

  tags = {
    Name                                       = "${var.ClusterBaseName}-PublicSubnet2"
    "kubernetes.io/role/elb"                   = "1"
    "kubernetes.io/cluster/${var.ClusterBaseName}" = "shared"
  }
}

resource "aws_subnet" "public_subnet3" {
  vpc_id                  = aws_vpc.eks_vpc.id
  cidr_block              = var.PublicSubnet3Block
  availability_zone       = var.AvailabilityZone3
  map_public_ip_on_launch = true

  tags = {
    Name                                       = "${var.ClusterBaseName}-PublicSubnet3"
    "kubernetes.io/role/elb"                   = "1"
    "kubernetes.io/cluster/${var.ClusterBaseName}" = "shared"
  }
}

##############################
# Internet Gateway & Routes
##############################
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.eks_vpc.id

  tags = {
    Name = "${var.ClusterBaseName}-igw"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.eks_vpc.id

  tags = {
    Name = "${var.ClusterBaseName}-PublicSubnetRouteTable"
  }
}

resource "aws_route" "public_route" {
  route_table_id         = aws_route_table.public_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public1_assoc" {
  subnet_id      = aws_subnet.public_subnet1.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public2_assoc" {
  subnet_id      = aws_subnet.public_subnet2.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public3_assoc" {
  subnet_id      = aws_subnet.public_subnet3.id
  route_table_id = aws_route_table.public_rt.id
}

##############################
# IAM Roles for EKS Cluster & Node Group
##############################

# Role for EKS Cluster Control Plane
resource "aws_iam_role" "eks_cluster_role" {
  name = "${var.ClusterBaseName}-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "eks.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

# Role for EKS Node Group
resource "aws_iam_role" "eks_node_role" {
  name = "${var.ClusterBaseName}-eks-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "ec2_registry_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

##############################
# EKS Cluster
##############################
resource "aws_eks_cluster" "eks_cluster" {
  name     = var.ClusterBaseName
  role_arn = aws_iam_role.eks_cluster_role.arn

  vpc_config {
    subnet_ids = [
      aws_subnet.public_subnet1.id,
      aws_subnet.public_subnet2.id,
      aws_subnet.public_subnet3.id,
    ]
    endpoint_public_access  = true
    endpoint_private_access = false
  }

  version = var.KubernetesVersion

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
  ]
}

##############################
# EKS Node Group
##############################
resource "aws_eks_node_group" "eks_node_group" {
  cluster_name    = aws_eks_cluster.eks_cluster.name
  node_group_name = "ng1"
  node_role_arn   = aws_iam_role.eks_node_role.arn
  subnet_ids      = [
    aws_subnet.public_subnet1.id,
    aws_subnet.public_subnet2.id,
    aws_subnet.public_subnet3.id,
  ]

  scaling_config {
    desired_size = var.WorkerNodeCount
    max_size     = var.WorkerNodeCount + 2
    min_size     = max(var.WorkerNodeCount - 1, 1)
  }

  instance_types = [var.WorkerNodeInstanceType]
  disk_size      = var.WorkerNodeVolumesize
  version        = var.KubernetesVersion

  remote_access {
    ec2_ssh_key = var.KeyName
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.ec2_registry_policy,
  ]
}

##############################
# IAM Role for Bastion Host
##############################
resource "aws_iam_role" "bastion_role" {
  name = "${var.ClusterBaseName}-bastion-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_instance_profile" "bastion_profile" {
  name = "${var.ClusterBaseName}-bastion-profile"
  role = aws_iam_role.bastion_role.name
}

resource "aws_iam_role_policy_attachment" "bastion_eks_policy" {
  role       = aws_iam_role.bastion_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "bastion_ec2_policy" {
  role       = aws_iam_role.bastion_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

resource "aws_iam_role_policy_attachment" "bastion_s3_policy" {
  role       = aws_iam_role.bastion_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role_policy" "bastion_eks_describe_policy" {
  name = "${var.ClusterBaseName}-bastion-eks-describe-policy"
  role = aws_iam_role.bastion_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = "eks:DescribeCluster",
        Resource = "arn:aws:eks:${var.TargetRegion}:${data.aws_caller_identity.current.account_id}:cluster/${var.ClusterBaseName}"
      }
    ]
  })
}

##############################
# Kubernetes Provider
##############################
provider "kubernetes" {
  host                   = aws_eks_cluster.eks_cluster.endpoint
  token                  = data.aws_eks_cluster_auth.eks_auth.token
  cluster_ca_certificate = base64decode(aws_eks_cluster.eks_cluster.certificate_authority[0].data)
}

data "aws_eks_cluster_auth" "eks_auth" {
  name = aws_eks_cluster.eks_cluster.name
}

resource "kubernetes_config_map" "aws_auth" {
  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
  }

  data = {
    mapRoles = <<YAML
- rolearn: ${aws_iam_role.eks_node_role.arn}
  username: system:node:{{EC2PrivateDNSName}}
  groups:
    - system:bootstrappers
    - system:nodes
- rolearn: ${aws_iam_role.bastion_role.arn}
  username: myeks-bastion
  groups:
    - system:masters
YAML
  }

  depends_on = [
    aws_eks_cluster.eks_cluster
  ]
}

##############################
# Bastion Host (for management)
##############################

# Security Group for Bastion Host
resource "aws_security_group" "bastion_sg" {
  name        = "${var.ClusterBaseName}-bastion-sg"
  description = "Security group for bastion host"
  vpc_id      = aws_vpc.eks_vpc.id

  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.ClusterBaseName}-bastion-sg"
  }
}

# Bastion Host EC2 Instance
resource "aws_instance" "bastion" {
  ami                         = data.aws_ssm_parameter.latest_ami.value
  instance_type               = var.BastionInstanceType
  key_name                    = var.KeyName
  subnet_id                   = aws_subnet.public_subnet1.id
  vpc_security_group_ids      = [aws_security_group.bastion_sg.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.bastion_profile.name

  depends_on = [
    aws_eks_cluster.eks_cluster,
    aws_eks_node_group.eks_node_group,
  ]

  user_data = <<-EOF
    #!/bin/bash
    hostnamectl --static set-hostname "${var.ClusterBaseName}-bastion-EC2"
    echo 'alias vi=vim' >> /etc/profile
    echo "sudo su -" >> /home/ec2-user/.bashrc

    sed -i "s/UTC/Asia\/Seoul/g" /etc/sysconfig/clock
    ln -sf /usr/share/zoneinfo/Asia/Seoul /etc/localtime

    yum -y install tree jq git htop lynx unzip

    curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.26.15/2024-12-12/bin/linux/amd64/kubectl
    install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

    curl -s https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash

    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip >/dev/null 2>&1
    sudo ./aws/install
    complete -C '/usr/local/bin/aws_completer' aws
    echo 'export AWS_PAGER=""' >>/etc/profile
    export AWS_DEFAULT_REGION=${var.TargetRegion}
    echo "export AWS_DEFAULT_REGION=$AWS_DEFAULT_REGION" >> /etc/profile

    wget https://github.com/andreazorzetto/yh/releases/download/v0.4.0/yh-linux-amd64.zip
    unzip yh-linux-amd64.zip
    mv yh /usr/local/bin/

    curl -LO https://github.com/kubernetes-sigs/krew/releases/download/v0.4.3/krew-linux_amd64.tar.gz
    tar zxvf krew-linux_amd64.tar.gz
    ./krew-linux_amd64 install krew
    export PATH="$PATH:/root/.krew/bin"
    echo 'export PATH="$PATH:/root/.krew/bin"' >> /etc/profile

    kubectl krew install ctx ns get-all df-pv neat

    echo 'source <(kubectl completion bash)' >> /etc/profile
    echo 'alias k=kubectl' >> /etc/profile
    echo 'complete -F __start_kubectl k' >> /etc/profile

    curl -LO "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_Linux_amd64.tar.gz"
    tar -xzf eksctl_Linux_amd64.tar.gz -C /usr/local/bin

    curl -L https://github.com/stern/stern/releases/download/v1.32.0/stern_1.32.0_linux_amd64.tar.gz | tar -xz -C /usr/local/bin stern
    chmod +x /usr/local/bin/stern

    git clone https://github.com/jonmosco/kube-ps1.git /root/kube-ps1
    cat <<"EOT" >> /root/.bash_profile
    source /root/kube-ps1/kube-ps1.sh
    KUBE_PS1_SYMBOL_ENABLE=false
    function get_cluster_short() {
      echo "$1" | cut -d . -f1
    }
    KUBE_PS1_CLUSTER_FUNCTION=get_cluster_short
    KUBE_PS1_SUFFIX=') '
    PS1='$(kube_ps1)'$PS1
    EOT

    amazon-linux-extras install docker -y
    systemctl start docker && systemctl enable docker

    aws eks update-kubeconfig --region ${var.TargetRegion} --name ${var.ClusterBaseName}

    aws configure set default.region ${var.TargetRegion}
    aws configure set default.output json

    export CLUSTER_NAME=${var.ClusterBaseName}
    export KUBERNETES_VERSION=${var.KubernetesVersion}
    export VPCID=$(aws ec2 describe-vpcs --filters "Name=tag:Name,Values=$CLUSTER_NAME-VPC" | jq -r .Vpcs[].VpcId)
    export PubSubnet1=$(aws ec2 describe-subnets --filters Name=tag:Name,Values="$CLUSTER_NAME-PublicSubnet1" --query "Subnets[0].[SubnetId]" --output text)
    export PubSubnet2=$(aws ec2 describe-subnets --filters Name=tag:Name,Values="$CLUSTER_NAME-PublicSubnet2" --query "Subnets[0].[SubnetId]" --output text)
    export PubSubnet3=$(aws ec2 describe-subnets --filters Name=tag:Name,Values="$CLUSTER_NAME-PublicSubnet3" --query "Subnets[0].[SubnetId]" --output text)
  EOF

  tags = {
    Name = "${var.ClusterBaseName}-bastion"
  }
}

##############################
# Outputs
##############################
output "cluster_endpoint" {
  description = "EKS Cluster Endpoint"
  value       = aws_eks_cluster.eks_cluster.endpoint
}

output "cluster_certificate_authority_data" {
  description = "EKS Cluster Certificate Authority Data"
  value       = aws_eks_cluster.eks_cluster.certificate_authority[0].data
}

output "cluster_name" {
  description = "EKS Cluster Name"
  value       = aws_eks_cluster.eks_cluster.name
}

output "bastion_public_ip" {
  description = "Public IP of the bastion host"
  value       = aws_instance.bastion.public_ip
}
