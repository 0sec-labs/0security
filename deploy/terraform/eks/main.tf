# An EKS cluster for the 0 console: one replica, one EBS volume.
# Not applied by the maintainers against a real AWS account. Run `terraform plan` and read it first.

provider "aws" {
  region = var.region
}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, 2)
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.16"

  name = var.cluster_name
  cidr = var.vpc_cidr
  azs  = local.azs

  private_subnets = [for i, _ in local.azs : cidrsubnet(var.vpc_cidr, 4, i)]
  public_subnets  = [for i, _ in local.azs : cidrsubnet(var.vpc_cidr, 8, 200 + i)]

  enable_nat_gateway = true
  single_nat_gateway = true

  public_subnet_tags  = { "kubernetes.io/role/elb" = 1 }
  private_subnet_tags = { "kubernetes.io/role/internal-elb" = 1 }
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.31"

  cluster_name    = var.cluster_name
  cluster_version = var.cluster_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_endpoint_public_access       = length(var.cluster_endpoint_public_access_cidrs) > 0
  cluster_endpoint_private_access      = true
  cluster_endpoint_public_access_cidrs = var.cluster_endpoint_public_access_cidrs

  enable_cluster_creator_admin_permissions = true
  enable_irsa                              = true

  cluster_addons = {
    coredns    = {}
    kube-proxy = {}
    vpc-cni = {
      # Enforces the chart's NetworkPolicy.
      configuration_values = jsonencode({ enableNetworkPolicy = "true" })
    }
    aws-ebs-csi-driver = {
      service_account_role_arn = module.ebs_csi_irsa.iam_role_arn
    }
  }

  eks_managed_node_groups = {
    default = {
      instance_types = var.node_instance_types
      min_size       = 1
      max_size       = 2
      desired_size   = 1
      disk_size      = 50
    }
  }
}

module "ebs_csi_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.48"

  role_name             = "${var.cluster_name}-ebs-csi"
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }
}

# The console's own identity: IRSA, so no AWS key is stored anywhere.
data "aws_iam_policy_document" "bedrock" {
  count = length(var.bedrock_model_arns) > 0 ? 1 : 0

  statement {
    actions   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
    resources = var.bedrock_model_arns
  }
}

resource "aws_iam_policy" "bedrock" {
  count  = length(var.bedrock_model_arns) > 0 ? 1 : 0
  name   = "${var.cluster_name}-zero-bedrock"
  policy = data.aws_iam_policy_document.bedrock[0].json
}

module "zero_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.48"

  role_name = "${var.cluster_name}-zero"
  role_policy_arns = length(var.bedrock_model_arns) > 0 ? {
    bedrock = aws_iam_policy.bedrock[0].arn
  } : {}

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["${var.namespace}:zero"]
    }
  }
}

# EBS gp3 storage class for the console's volume. WaitForFirstConsumer places the
# volume in the zone of the node that runs the pod.
resource "kubernetes_storage_class_v1" "gp3" {
  metadata {
    name = "zero-gp3"
  }
  storage_provisioner    = "ebs.csi.aws.com"
  reclaim_policy         = "Retain"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true
  parameters = {
    type      = "gp3"
    encrypted = "true"
  }
  depends_on = [module.eks]
}

resource "helm_release" "zero" {
  name             = "zero"
  chart            = "${path.module}/../../helm/zero"
  namespace        = var.namespace
  create_namespace = true

  values = compact([
    yamlencode({
      persistence    = { storageClassName = kubernetes_storage_class_v1.gp3.metadata[0].name }
      secrets        = { existingSecret = var.access_token_secret_name }
      serviceAccount = { annotations = { "eks.amazonaws.com/role-arn" = module.zero_irsa.iam_role_arn } }
      model          = { awsRegion = var.region }
      ingress        = { enabled = var.hostname != "", host = var.hostname }
    }),
    var.chart_values,
  ])

  depends_on = [module.eks]
}
