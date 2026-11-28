# TLS termination and load balancing for two replicas. Caddy sets X-Forwarded-For/Proto/Host itself and
# replaces any value a client sent, which is what --trusted-proxy relies on.
{$ZERO_DOMAIN} {
	encode zstd gzip
	reverse_proxy zero1:48123 zero2:48123 {
		# A browser stays on one replica while it is ready, because a live Thread belongs to one replica.
		lb_policy cookie
		health_uri /readyz
		health_interval 5s
		health_timeout 3s
		health_status 200
		health_headers {
			Host {$ZERO_DOMAIN}
		}
		# Retry the other replica when one refuses the connection, for example while it restarts.
		lb_try_duration 5s
	}
}
