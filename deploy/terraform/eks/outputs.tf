output "cluster_name" {
  description = "Name of the EKS cluster."
  value       = module.eks.cluster_name
}

output "kubeconfig_command" {
  description = "Command that writes the cluster to your kubeconfig."
  value       = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name}"
}

output "zero_role_arn" {
  description = "IAM role the console assumes through its service account."
  value       = module.zero_irsa.iam_role_arn
}
