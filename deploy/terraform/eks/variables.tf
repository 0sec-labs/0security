variable "region" {
  description = "AWS region for the cluster."
  type        = string
}

variable "cluster_name" {
  description = "Name of the EKS cluster."
  type        = string
  default     = "zero"
}

variable "cluster_version" {
  description = "Kubernetes version."
  type        = string
  default     = "1.31"
}

variable "vpc_cidr" {
  description = "CIDR block of the new VPC."
  type        = string
  default     = "10.40.0.0/16"
}

variable "node_instance_types" {
  description = "Instance types of the node group. The console needs 2 vCPU and 4 GB plus headroom per concurrent Thread."
  type        = list(string)
  default     = ["m6i.xlarge"]
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "CIDRs allowed to reach the Kubernetes API. Narrow this to your office or VPN ranges."
  type        = list(string)
  default     = []
}

variable "namespace" {
  description = "Kubernetes namespace of the console."
  type        = string
  default     = "zero"
}

variable "hostname" {
  description = "Public host name of the console, for example 0.example.com. Leave empty to reach it with kubectl port-forward."
  type        = string
  default     = ""
}

variable "access_token_secret_name" {
  description = "Name of an existing Kubernetes Secret in the namespace with ZERO_ACCESS_TOKEN and any model or OIDC secrets. Create it before you apply. Leave empty to let the console generate a token."
  type        = string
  default     = ""
}

variable "bedrock_model_arns" {
  description = "Bedrock model or inference profile ARNs the console may invoke. Empty grants no Bedrock access."
  type        = list(string)
  default     = []
}

variable "chart_values" {
  description = "Extra Helm values, as YAML, merged over the defaults. Set model.provider, model.name and team.config here."
  type        = string
  default     = ""
}
