# CCSecOps
This quickstart guide for Calico Network Policy and Security options for Kubernetes clusters is just an extension of Tigera's documentation for their Software-as-a-Service offering 'Calico Cloud' - https://docs.calicocloud.io/get-started/quickstart

This guide also assumes that you have already created a supported Kubernetes cluster, have installed Project Calico installed on the master node, and have started a trial of Calico Cloud.

At the time of writing this post, you can easily hook-up your existing cluster to Calico Cloud by running a single cURL command provided to you by the team at Tigera. The command should look similar to the below example:

```
curl -s https://installer.calicocloud.io/XYZ_your_business_install.sh | bash
```

# Modify the Felix agent log flush interval
Should help us see data update quicker during our workshop. This is not a recommended configuration for production environments.

```
kubectl patch felixconfiguration.p default -p '{"spec":{"flowLogsFlushInterval":"10s"}}'
kubectl patch felixconfiguration.p default -p '{"spec":{"dnsLogsFlushInterval":"10s"}}'
kubectl patch felixconfiguration.p default -p '{"spec":{"flowLogsFileAggregationKindForAllowed":1}}'
```

# Deploying a test application for threat visibility

If your cluster does not have applications, you can use the following storefront application. This YAML file creates a bunch of NameSpaces, ServiceAccounts, Deployments and Services responsible for real-world visibility. This 'Storefront' namespace contains the standard microservices, frontend, backend and logging components we would expect in a cloud-native architecture.

```
kubectl apply -f https://installer.calicocloud.io/storefront-demo.yaml
```

Check which pods are running within the newly added 'Storefront' namespace. 
Showing the labels associated with the pods will help us later with policy configuration.

```
kubectl get pod -n storefront --show-labels
```

# Creating a zone-based architecture:
One of the most widely adopted deployment models with traditional firewalls is using a zone-based architecture. This
involves putting the frontend of an application in a DMZ, business logic services in Trusted zone, and our backend data
store in Restricted - all with controls on how zones can communicate with each other. For our storefront application, it
would look something like the following:


# Start with a Demilitarized Zone (DMZ):
The goal of a DMZ is to add an extra layer of security to an organization's local area network. 
A protected and monitored network node that faces outside the internal network can access what is exposed in the DMZ, while the rest of the organization's network is safe behind a firewall.

```
cat << EOF > dmz.yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: default.dmz
  namespace: storefront
spec:
  tier: default
  order: 0
  selector: fw-zone == "dmz"
  serviceAccountSelector: ''
  ingress:
    - action: Allow
      source:
        nets:
          - 18.0.0.0/16
      destination: {}
    - action: Deny
      source: {}
      destination: {}
  egress:
    - action: Allow
      source: {}
      destination:
        selector: fw-zone == "trusted"||app == "logging"
    - action: Deny
      source: {}
      destination: {}
  types:
    - Ingress
    - Egress
EOF
```

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/CCSecOps/main/ZBA/dmz.yaml
```

# After the DMZ, we need a Trusted Zone
The trusted zone represents a group of network addresses from which the Personal firewall allows some inbound traffic using default settings.

```
cat << EOF > trusted.yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: default.trusted
  namespace: storefront
spec:
  tier: default
  order: 10
  selector: fw-zone == "trusted"
  serviceAccountSelector: ''
  ingress:
    - action: Allow
      source:
        selector: fw-zone == "dmz"
      destination: {}
    - action: Allow
      source:
        selector: fw-zone == "trusted"
      destination: {}
    - action: Deny
      source: {}
      destination: {}
  egress:
    - action: Allow
      source: {}
      destination:
        selector: fw-zone == "trusted"
    - action: Allow
      source: {}
      destination:
        selector: fw-zone == "restricted"
    - action: Deny
      source: {}
      destination: {}
  types:
    - Ingress
    - Egress
EOF
```

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/CCSecOps/main/ZBA/trusted.yaml
```

# Finally, we configure the Restricted Zone
A restricted zone supports functions to which access must be strictly controlled; direct access from an uncontrolled network should not be permitted. In a large enterprise, several network zones might be designated as restricted.

```
cat << EOF > restricted.yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: default.restricted
  namespace: storefront
spec:
  tier: default
  order: 20
  selector: fw-zone == "restricted"
  serviceAccountSelector: ''
  ingress:
    - action: Allow
      source:
        selector: fw-zone == "trusted"
      destination: {}
    - action: Allow
      source:
        selector: fw-zone == "restricted"
      destination: {}
    - action: Deny
      source: {}
      destination: {}
  egress:
    - action: Allow
      source: {}
      destination: {}
  types:
    - Ingress
    - Egress
EOF
```

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/CCSecOps/main/ZBA/restricted.yaml
```

<img width="564" alt="Screenshot 2021-06-10 at 10 57 45" src="https://user-images.githubusercontent.com/82048393/121505461-c465ee00-c9da-11eb-804c-afb49814fd9f.png">


# Subscribing to a malicious threatfeed
Project Calico simplifies the process of dynamic threat feed subscription via a Calico construct known as 'NetworkSets'.
A network set resource represents an arbitrary set of IP subnetworks/CIDRs, allowing it to be matched by Calico policy. 
Network sets are useful for applying policy to traffic coming from (or going to) external, non-Calico, networks.
https://docs.tigera.io/threat/suspicious-ips

```
cat << EOF > feodo-tracker.yaml
apiVersion: projectcalico.org/v3
kind: GlobalThreatFeed
metadata:
  name: feodo-tracker
spec:
  content: IPSet
  pull:
    http:
      url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
  globalNetworkSet:
    labels:
      threat-feed: feodo
EOF
```

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/CCSecOps/main/ThreatFeeds/feodo-tracker.yaml
```

Verify the GlobalNetworkSet is configured correctly:

```
kubectl get globalnetworksets threatfeed.feodo-tracker -o yaml
```

# Build a policy based on the threat feed

We will start by creating a tier called 'security'.

```
cat << EOF > security.yaml
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: security
spec:
  order: 600
EOF  
```

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/CCSecOps/main/Tiers/security.yaml
```

If DNS traffic is blocked to the storefront namespace, we will need to allow DNS via this policy:

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/CCSecOps/main/SecurityPolicies/dns-allow.yaml
```

Notice how the below 'block-feodo' policy is related to the 'security' tier - name: security.block-feodo

```
cat << EOF > feodo-policy.yaml
apiVersion: projectcalico.org/v3
kind: StagedGlobalNetworkPolicy
metadata:
  name: security.block-feodo
spec:
  tier: security
  order: 210
  selector: projectcalico.org/namespace != "acme"
  namespaceSelector: ''
  serviceAccountSelector: ''
  egress:
    - action: Deny
      source: {}
      destination:
        selector: threatfeed == "feodo"
  doNotTrack: false
  applyOnForward: false
  preDNAT: false
  types:
    - Egress
EOF
```

Applies to anything that IS NOT listed with the namespace selector = 'acme'
```
selector: projectcalico.org/namespace != "acme"
```

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/CCSecOps/main/SecurityPolicies/block-feodo.yaml
```

# Build policies through the Policy Recommendation Engine
We will start by creating a tier called 'development'.

```
cat << EOF > development.yaml
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: development
spec:
  order: 700
EOF  
```

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/CCSecOps/main/Tiers/development.yaml
```

# Sample Staged Network Policy via Policy Recommendation Engine

Security is often not the first thing you think about when configuring a cluster. By the time you decide to segment your traffic, there are dozens of services already running and connecting to each other. Setting up your security policy in a running environment can be very difficult, and becomes more complex the larger your cluster grows.

<img width="529" alt="Screenshot 2021-06-09 at 21 28 55" src="https://user-images.githubusercontent.com/82048393/121503927-6f75a800-c9d9-11eb-87ff-04c9caab739c.png">

The platform logs all traffic flows and uses this data to form a baseline of traffic flows among microservices. The baseline is then used to generate a set of recommended policies that will lock down your cluster while maintaining those existing connections. These policies can subsequently be reviewed and modified, if necessary, before staging or enforcing in your cluster.

```
apiVersion: projectcalico.org/v3
kind: StagedNetworkPolicy
metadata:
  name: default.acme-microservice1-57c477fdd7
  namespace: acme
spec:
  tier: default
  selector: app == "acme-microservice1"
  serviceAccountSelector: ''
  ingress:
    - action: Allow
      protocol: TCP
      source:
        selector: app == "acme-microservice2"
      destination:
        ports:
          - '8080'
  egress:
    - action: Allow
      protocol: TCP
      source: {}
      destination:
        selector: app == "acme-microservice2"
        ports:
          - '8080'
    - action: Allow
      protocol: UDP
      source: {}
      destination:
        selector: k8s-app == "kube-dns"
        namespaceSelector: projectcalico.org/name == "kube-system"
        ports:
          - '53'
  types:
    - Ingress
    - Egress
```

NB: There is no need to apply this YAML file as we can do this easily from the web user interface.
Recommended policies are registered in the 'default' tier. You can easily drag into the 'development' tier.


ie:
```
apiVersion: projectcalico.org/v3
kind: StagedNetworkPolicy
metadata:
  name: development.acme-microservice1-57c477fdd7
  namespace: acme
```

This will not break the policy - which allows for simplified segmentation of policies.
We can follow the same process for our 2nd 'acme' microservice'.



# Anomaly Detection Jobs

For the management or standalone cluster:
```
curl https://docs.tigera.io/manifests/threatdef/ad-jobs-deployment.yaml -O
```

For the managed cluster:
```
curl https://docs.tigera.io/manifests/threatdef/ad-jobs-deployment-managed.yaml -O
```

Since we are managing a standalone cluster, we insert your cluster name into the 'ad-jobs-deployment' YAML file:
```
sed -i 's/CLUSTER_NAME/tigera-internal-managed-10-0-1-118/g' ad-jobs-deployment.yaml
```

Confirm the changes were applied within the YAML file:
```
cat ad-jobs-deployment.yaml | grep tigera-internal-managed-10-0-1-118
```

For the management or standalone cluster, make this change:
```
kubectl apply -f ad-jobs-deployment.yaml
```

You can configure the jobs using the environment variables. 

```
env:
 - name: AD_max_docs
   value: "2000000"
 - name: AD_train_interval_minutes
   value: "20"
 - name: AD_port_scan_threshold
   value: "500"
 - name: AD_DnsLatency_IsolationForest_n_estimators
   value: "100"
```

You can use vi to make changes to your deployment manifest (the yaml file):

```
vi ad-jobs-deployment.yaml
```

For a list of jobs are their respective values, visit this Tigera doc:
https://docs.tigera.io/threat/anomaly-detection/customizing

The below anomaly detection jobs run indefinitely:
```
kubectl get pods -n tigera-intrusion-detection -l app=anomaly-detection
```

Use the pod logs to monitor the job execution and health.
```
kubectl logs <pod_name> -n tigera-intrusion-detection | grep INFO
```

You can see that the jobs go through training cycles. 
The more cycles it runs, the more it can learn from your data.

# Anonymization Attacks

Add threat feed to the cluster. For EJR VPN:
```
kubectl apply -f https://docs.tigera.io/manifests/threatdef/ejr-vpn.yaml
```

For Tor Bulk Exit Feed:
```
kubectl apply -f https://docs.tigera.io/manifests/threatdef/tor-exit-feed.yaml
```

Additionally, feeds can be checked using following command:
```
kubectl get globalthreatfeeds 
```

At this point, we should have 3 threat feeds running in our cluster with Calico Enterprise:

```
NAME                 CREATED AT
ejr-vpn              2021-06-10T10:32:55Z
feodo-tracker        2021-06-10T09:37:36Z
tor-bulk-exit-list   2021-06-10T10:33:06Z
```


Run the below command to confirm the source URL of your threat feed
```
kubectl get globalthreatfeeds.tor-bulk-exit-list -o yaml
```

It should be:
```
https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1
```

# Deploying a rogue pod into the hardened environment

Run the following command to creare a rogue workload that will probe for vulnerable or exposed services within the cluster:

```
kubectl apply -f https://installer.calicocloud.io/rogue-demo.yaml -n storefront
```

To confirm your rogue pod was successfully deployed to the 'default' namespace, run the below command:

```
kubectl get pods -n storefront --show-labels
```

After you are done evaluating your network policies in with the rogue pod, you can remove it by running:

```
kubectl delete -f https://installer.calicocloud.io/rogue-demo.yaml -n storefront
```


# Configuring Honeypods

Create the Tigera-Internal namespace for this honeypod service:
```
kubectl apply -f https://docs.tigera.io/manifests/threatdef/honeypod/common.yaml
```

Get the Tigera Pull Secret from the Tigera Guardian namespace:
```
kubectl get secrets tigera-pull-secret -n tigera-guardian -o yaml
```

We need to get the Tigera pull secret output yaml, and put it into a 'pull-secret.yaml' file:
```
kubectl get secret tigera-pull-secret -n tigera-guardian -o yaml > pull-secret.yaml
```

Apply changes to the below pull secret
```
kubectl apply -f pull-secret.yaml
```





# Quarantining the rogue pod
Traditionally, when we block a network packet we lose all context of the threat actor.
Calico Network Policies allow you to block AND log the activity, therefore tracking the rich metadata surrounding the malicious actor.

```
cat << EOF > quarantine.yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: security.quarantine
spec:
  tier: security
  order: 100
  selector: quarantine == "true"
  namespaceSelector: ''
  serviceAccountSelector: ''
  ingress:
    - action: Log
      source: {}
      destination: {}
    - action: Deny
      source: {}
      destination: {}
  egress:
    - action: Log
      source: {}
      destination: {}
    - action: Deny
      source: {}
      destination: {}
  doNotTrack: false
  applyOnForward: false
  preDNAT: false
  types:
    - Ingress
    - Egress
EOF
```

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/CCSecOps/main/SecurityPolicies/quarantine.yaml
```

Add the quarantine label to our rogue pod, and monitor changes to the quarantine policy.
```
kubectl label pod attacker-app-5f8d5574bf-4ljvx -n storefront quarantine=true
```

It's always good practice to double-check your label is correctly applied
```
kubectl get pod attacker-app-5f8d5574bf-4ljvx -n storefront --show-labels
```

# Finally, you need a Default/Deny Policy

We recommend creating an implicit default deny policy for your Kubernetes pods, regardless if you use Calico Cloud or Kubernetes network policy. 
This ensures that unwanted traffic is denied by default. Note that implicit default deny policy always occurs last; if any other policy allows the traffic, then the deny does not come into effect. The deny is executed only after all other policies are evaluated.
https://docs.tigera.io/security/kubernetes-default-deny#default-denyallow-behavior

```
cat << EOF > default-deny.yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: default.default-deny
spec:
  tier: default
  selector: all()
  namespaceSelector: ''
  serviceAccountSelector: ''
  doNotTrack: false
  applyOnForward: false
  preDNAT: false
  types:
    - Ingress
    - Egress
EOF
```

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/CCSecOps/main/ZBA/default-deny.yaml
```
