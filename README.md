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
        selector: type == "public"
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


Notice how the below 'block-feodo' policy is related to the 'security' tier - name: security.block-feodo

```
cat << EOF > feodo-policy.yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
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
  order: 500
EOF  
```

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/CCSecOps/main/Tiers/development.yaml
```

# Sample Staged Network Policy via Policy Recommendation Engine


```
INSERT HERE
```


# SAMPLE Anomaly Detection Scripts

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
```

You can use vi to make changes to your deployment manifest (the yaml file):

```
vi ad-jobs-deployment.yaml
```

For a list of jobs are their respective values, visit this Tigera doc:
https://docs.tigera.io/threat/anomaly-detection/customizing




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
kubectl apply -f quarantine.yaml
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
kubectl apply -f default-deny.yaml
```

# Compliance Reporting

Ensure that the compliance-benchmarker is running, and that the cis-benchmark report type is installed:

```
kubectl get -n tigera-compliance daemonset compliance-benchmarker
kubectl get globalreporttype cis-benchmark
```


In this section we will walk through a quick example of how to use Calico Cloud to produce dynamic compliance
reports that allow you to assess the state of compliance that is in lock step with your CI/CD pipeline.
https://docs.tigera.io/compliance/compliance-reports-cis

```
cat << EOF > daily-cis-results.yaml
apiVersion: projectcalico.org/v3
kind: GlobalReport
metadata:
  name: daily-cis-results
  labels:
    deployment: production
spec:
  reportType: cis-benchmark
  schedule: 0 * * * *
  cis:
    highThreshold: 100
    medThreshold: 50
    includeUnscoredTests: true
    numFailedTests: 5
    resultsFilters:
    - benchmarkSelection: { kubernetesVersion: "1.13" }
      exclude: ["1.1.4", "1.2.5"]
EOF
```
 
```
kubectl apply -f daily-cis-results.yaml
```
 
CIS benchmarks are best practices for the secure configuration of a target system - in our case Kubnernetes. 
Calico Cloud supports a number of GlobalReport types that can be used for continuous compliance, and CIS benchmarks is one of them.

To view the status of a report, you must use the kubectl command. For example:

```
kubectl get globalreports.projectcalico.org daily-cis-results -o yaml
```

A quick way to build these reports is from pre-configured examples:

```
kubectl apply -f https://raw.githubusercontent.com/xxradar/app_routable_demo/v1.0/calico_ee/globalreport/hourly-networkaccess-report.yaml
```
```
kubectl apply -f https://raw.githubusercontent.com/xxradar/app_routable_demo/v1.0/calico_ee/globalreport/hourly-inventory-report.yaml
```

