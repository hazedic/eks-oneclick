# AWS EKS Automation with Terraform

## Introduction

This project converts the **AWS EKS cluster one-click deployment CloudFormation code** used in the 3rd lecture of Inflearn's **['CloudNet@와 함께하는 Amazon EKS 기본 강의'](https://www.inflearn.com/course/amazon-eks-%EA%B8%B0%EB%B3%B8-%EA%B0%95%EC%9D%98/)** into **Terraform** code.

## Prerequisites

Before running Terraform, complete the following steps:

1. Modify the `terraform.tfvars` file and set the `KeyName` value to your EC2 key pair name.

## Deployment Guide

Follow these steps to deploy an AWS EKS cluster using Terraform:

```sh
$ git clone https://github.com/hazedic/eks-oneclick.git
$ cd eks-oneclick
$ terraform init
$ terraform plan
$ terraform apply
```

## Important Notes

- The bastion server's ingress rule (main.tf, line 326) currently allows connections from all IP addresses (`0.0.0.0/0`), which may pose security risks. It is recommended to restrict access to trusted IP ranges.
- Ensure that AWS CLI and Terraform are properly set up before applying Terraform.
- Running `terraform apply` may incur costs. To clean up resources after use, run `terraform destroy`.