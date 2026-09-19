output "instance_id" {
  description = "ID of the WAF instance. Used to open a session and to verify the deployment."
  value       = aws_instance.waf.id
}

# The Elastic IP, not the instance's own address: it stays the same across
# instance replacement, so test tools can keep one target.
output "public_ip" {
  description = "Public address clients and test tools reach the WAF on"
  value       = aws_eip.waf.public_ip
}
