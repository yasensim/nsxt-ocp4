# nsxt-ocp4
Helpers for the NSX-T BETA integration with Openshift 4.3




1 Destroy machines using terraform
terraform destroy
python nsx_policy_cleanup.py --mgr-ip=10.114.209.48 -u admin -p VMwareVMware1! -c ocp4 --no-warning -r
2 run the first script, that will generate the ignition files, and copy over NCP manifests and create manifests.
ocp4_script.sh
4 You need to copy the contents of master.ign and worker.ign to terraform.tfvars 
    cat vsphere/master.ign >> installer/upi/vsphere/terraform.tfvars
        cat vsphere/worker.ign >> installer/upi/vsphere/terraform.tfvars
        5 Run terraform apply -auto-approve
        6 Ping all machines and make sure they are pingable
        7 run the copy and load script
        ocp4_script2.sh
        python tag_policy_ports.py
        While the files are being copied - you need to update tags for the logical ports.
        #On second terminalL
        
        do export KUBECONFIG=/root/openshift43/vsphere/auth/kubeconfig
        
        9 Set resolving for api to the bootstrap
        10 run openshift-install --dir=/root/openshift43/vsphere wait-for bootstrap-complete --log-level=DEBUG
        ./check_network_status.sh
        11 Set api to control-nodes
        12 run terraform apply -auto-approve -var 'bootstrap_complete=true'
        
        
        
        oc get nodes
        oc get pods -n nsx-system
        oc get pods --all-namespaces 
        
        
        
        oc patch configs.imageregistry.operator.openshift.io cluster --type merge --patch '{"spec":{"storage":{"emptyDir":{}}}}'
        watch -n5 oc get co
        ## when all completes
        openshift-install --dir=/root/openshift43/vsphere wait-for install-complete --log-level=DEBUG
        
        
        
        
        If API connection refused:
        ssh to bootstrap
        sudo su -
        mv /etc/kubernetes/manifests/* /tmp/
        systemctl restart bootkube
        