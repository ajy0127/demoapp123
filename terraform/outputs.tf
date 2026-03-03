output "app_public_ip" {
  description = "Public IP of the demo app EC2 instance (Elastic IP)"
  value       = aws_eip.demo_app.public_ip
}

output "app_url" {
  description = "URL to access the demo app"
  value       = "http://${aws_eip.demo_app.public_ip}:5000"
}

output "ecr_repository_url" {
  description = "ECR repository URL for pushing images"
  value       = aws_ecr_repository.demo_app.repository_url
}

output "ecr_repository_name" {
  description = "ECR repository name"
  value       = aws_ecr_repository.demo_app.name
}
