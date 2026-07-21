##############################################################################
# General note:
# - When no specific configuration is mentioned, default values have been used
#   as far as security was not compromised.
# Architecture notes:
# - The GCP Global external HTTP(S) Load Balancer is an anycast service at
#   Google's edge (GFE) and is NOT bound to a subnet the way a regional LB
#   is, even though the assignment's requirement mentioned "A Global HTTP 
#   Load Balancer in the public subnet";
# - The Compute Engine instance sits in the private subnet with NO external
#   IP. Outbound internet access (e.g. for OS patching) is provided via
#   Cloud NAT rather than a public IP.
# - The LB terminates TLS (443) at the edge and forwards plain HTTP (80) to
#   the backend instance, matching the required firewall posture exactly:
#     Internet  -> LB        : HTTPS/443
#     LB (GFE)  -> Instance  : HTTP/80
#     Trusted IP-> Instance  : SSH/22
# - Firewall rule for "LB -> instance" uses Google's documented GFE /
#   health-check source ranges (130.211.0.0/22, 35.191.0.0/16), which is
#   the actual mechanism GCP uses to identify LB-originated traffic.
##############################################################################

##############################################################################
# VPC + Subnets
##############################################################################

resource "google_compute_network" "vpc" {
  name                    = "my-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "public_subnet" {
  name          = "public-subnet"
  network       = google_compute_network.vpc.id
  region        = var.region
  ip_cidr_range = var.public_subnet_cidr
}

resource "google_compute_subnetwork" "private_subnet" {
  name                     = "private-subnet"
  network                  = google_compute_network.vpc.id
  region                   = var.region
  ip_cidr_range            = var.private_subnet_cidr
  private_ip_google_access = true
}

##############################################################################
# Cloud Router + Cloud NAT
##############################################################################

resource "google_compute_router" "router" {
  name    = "private-subnet-router"
  network = google_compute_network.vpc.id
  region  = var.region
}

resource "google_compute_router_nat" "nat" {
  name                               = "private-subnet-nat"
  router                             = google_compute_router.router.name
  region                             = var.region
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.private_subnet.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }
}

##############################################################################
# Firewall Rules
##############################################################################

resource "google_compute_firewall" "allow_https_to_lb" {
  name      = "allow-https-to-lb"
  network   = google_compute_network.vpc.id
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["lb-frontend"]
}

resource "google_compute_firewall" "allow_ssh_trusted" {
  name      = "allow-ssh-from-trusted-ip"
  network   = google_compute_network.vpc.id
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = [var.trusted_ssh_cidr]
  target_tags   = ["private-instance"]
}

resource "google_compute_firewall" "allow_http_from_lb" {
  name      = "allow-http-from-lb-to-instance"
  network   = google_compute_network.vpc.id
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"] # Google's documented GFE / health-check ranges for LBs
  target_tags   = ["private-instance"]
}

##############################################################################
# IAM service account for the VM
##############################################################################

resource "google_service_account" "vm_sa" {
  account_id   = "app-vm-sa"
  display_name = "VM-service-account"
}

# Only the roles that the VM would need to ship logs and metrics.
resource "google_project_iam_member" "vm_sa_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.vm_sa.email}"
}

resource "google_project_iam_member" "vm_sa_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.vm_sa.email}"
}

##############################################################################
# Compute Engine Instance
##############################################################################

resource "google_compute_instance" "app_vm" {
  name         = "app-vm"
  machine_type = var.instance_machine_type
  zone         = var.zone
  tags         = ["private-instance"]

  boot_disk {
    disk_encryption_key_raw = disk_encryption_key_rsa
    initialize_params {
      image = "debian-cloud/debian-13"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.private_subnet.id
  }

  service_account {
    email  = google_service_account.vm_sa.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

}

##############################################################################
# Load Balancer
##############################################################################

resource "google_compute_health_check" "http_health_check" {
  name                = "app-http-health-check"
  timeout_sec         = 5
  check_interval_sec  = 10

  http_health_check {
    port         = 80
  }
}

resource "google_compute_instance_group" "app_group" {
  name      = "app-instance-group"
  zone      = var.zone
  network   = google_compute_network.vpc.id
  instances = [google_compute_instance.app_vm.id]

  named_port {
    name = "http"
    port = 80
  }
}

resource "google_compute_backend_service" "app_backend" {
  name                  = "app-backend-service"
  protocol              = "HTTP"
  port_name             = "http"
  health_checks         = [google_compute_health_check.http_health_check.id]

  backend {
    group = google_compute_instance_group.app_group.id
  }
}

##############################################################################
# Global HTTPS Load Balancer
##############################################################################

resource "google_compute_url_map" "app_url_map" {
  name            = "app-url-map"
  default_service = google_compute_backend_service.app_backend.id
}

resource "google_compute_managed_ssl_certificate" "app_cert" {
  name = "app-managed-cert"

  managed {
    domains = [var.domain_name]
  }
}

resource "google_compute_target_https_proxy" "app_https_proxy" {
  name             = "app-https-proxy"
  url_map          = google_compute_url_map.app_url_map.id
  ssl_certificates = [google_compute_managed_ssl_certificate.app_cert.id]
}

resource "google_compute_global_address" "lb_ip" {
  name = "app-lb-ip"
}

resource "google_compute_global_forwarding_rule" "https_forwarding_rule" {
  name                  = "app-https-forwarding-rule"
  ip_address            = google_compute_global_address.lb_ip.address
  ip_protocol           = "TCP"
  port_range            = "443"
  target                = google_compute_target_https_proxy.app_https_proxy.id
}
