output "load_balancer_ip" {
  description = "Global external IP of the HTTPS Load Balancer. Point your DNS A record for var.domain_name at this."
  value       = google_compute_global_address.lb_ip.address
}

output "instance_name" {
  description = "Name of the private Compute Engine instance."
  value       = google_compute_instance.app_vm.name
}

output "instance_internal_ip" {
  description = "Internal IP of the Compute Engine instance (reachable only within the VPC / via SSH from the trusted CIDR)."
  value       = google_compute_instance.app_vm.network_interface[0].network_ip
}

output "service_account_email" {
  description = "Least-privilege service account attached to the VM."
  value       = google_service_account.vm_sa.email
}
