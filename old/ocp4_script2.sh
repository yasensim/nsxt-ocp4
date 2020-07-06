scp -i /root/.ssh/id_rsa nsx-ncp-rhel-3.0.0.34331552.tar core@10.114.16.10:/tmp/ &
scp -i /root/.ssh/id_rsa nsx-ncp-rhel-3.0.0.34331552.tar core@10.114.16.11:/tmp/ &
scp -i /root/.ssh/id_rsa nsx-ncp-rhel-3.0.0.34331552.tar core@10.114.16.12:/tmp/ &
scp -i /root/.ssh/id_rsa nsx-ncp-rhel-3.0.0.34331552.tar core@10.114.16.20:/tmp/ &
scp -i /root/.ssh/id_rsa nsx-ncp-rhel-3.0.0.34331552.tar core@10.114.16.21:/tmp/ &
scp -i /root/.ssh/id_rsa nsx-ncp-rhel-3.0.0.34331552.tar core@10.114.16.22:/tmp/ &
wait
ssh -i /root/.ssh/id_rsa core@10.114.16.10  "sudo podman load < /tmp/nsx-ncp-rhel-3.0.0.34331552.tar" &
ssh -i /root/.ssh/id_rsa core@10.114.16.11  "sudo podman load < /tmp/nsx-ncp-rhel-3.0.0.34331552.tar" &
ssh -i /root/.ssh/id_rsa core@10.114.16.12  "sudo podman load < /tmp/nsx-ncp-rhel-3.0.0.34331552.tar" &
ssh -i /root/.ssh/id_rsa core@10.114.16.20  "sudo podman load < /tmp/nsx-ncp-rhel-3.0.0.34331552.tar" &
ssh -i /root/.ssh/id_rsa core@10.114.16.21  "sudo podman load < /tmp/nsx-ncp-rhel-3.0.0.34331552.tar" &
ssh -i /root/.ssh/id_rsa core@10.114.16.22  "sudo podman load < /tmp/nsx-ncp-rhel-3.0.0.34331552.tar" &
wait
#ssh -i /root/.ssh/id_rsa core@10.114.16.10  "sudo podman image tag registry.local/3.0.0.34331552/nsx-ncp-rhel nsx-ncp"
#ssh -i /root/.ssh/id_rsa core@10.114.16.11  "sudo podman image tag registry.local/3.0.0.34331552/nsx-ncp-rhel nsx-ncp"
#ssh -i /root/.ssh/id_rsa core@10.114.16.12  "sudo podman image tag registry.local/3.0.0.34331552/nsx-ncp-rhel nsx-ncp"
#ssh -i /root/.ssh/id_rsa core@10.114.16.20  "sudo podman image tag registry.local/3.0.0.34331552/nsx-ncp-rhel nsx-ncp"
#ssh -i /root/.ssh/id_rsa core@10.114.16.21  "sudo podman image tag registry.local/3.0.0.34331552/nsx-ncp-rhel nsx-ncp"
#ssh -i /root/.ssh/id_rsa core@10.114.16.22  "sudo podman image tag registry.local/3.0.0.34331552/nsx-ncp-rhel nsx-ncp"

