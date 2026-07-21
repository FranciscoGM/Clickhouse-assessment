variable "project_id" {
  description = "GCP project ID to deploy into."
  type        = string
}

variable "region" {
  description = "GCP region for regional resources."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone for the Compute Engine instance."
  type        = string
  default     = "us-central1-a"
}

variable "trusted_ssh_cidr" {
  description = "CIDR range allowed to SSH into the private instance. Must NOT be 0.0.0.0/0."
  type        = string

  validation {
    condition     = var.trusted_ssh_cidr != "0.0.0.0/0"
    error_message = "trusted_ssh_cidr must not be 0.0.0.0/0. Provide a specific, trusted CIDR range."
  }
}

variable "domain_name" {
  description = "Domain name for the Google-managed SSL certificate used by the HTTPS Load Balancer."
  type        = string
}

variable "instance_machine_type" {
  description = "Machine type for the Compute Engine instance."
  type        = string
  default     = "e2-small"
}

variable "public_subnet_cidr" {
  description = "CIDR range for the public subnet."
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR range for the private subnet."
  type        = string
  default     = "10.0.2.0/24"
}
