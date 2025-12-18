# API Reference

Packages:

- [clusterpulse.io/v1alpha1](#clusterpulseiov1alpha1)

# clusterpulse.io/v1alpha1

Resource Types:

- [MonitorAccessPolicy](#monitoraccesspolicy)




## MonitorAccessPolicy
<sup><sup>[↩ Parent](#clusterpulseiov1alpha1 )</sup></sup>








<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
      <td><b>apiVersion</b></td>
      <td>string</td>
      <td>clusterpulse.io/v1alpha1</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b>kind</b></td>
      <td>string</td>
      <td>MonitorAccessPolicy</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b><a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#objectmeta-v1-meta">metadata</a></b></td>
      <td>object</td>
      <td>Refer to the Kubernetes API documentation for the fields of the `metadata` field.</td>
      <td>true</td>
      </tr><tr>
        <td><b><a href="#monitoraccesspolicyspec">spec</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#monitoraccesspolicystatus">status</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec
<sup><sup>[↩ Parent](#monitoraccesspolicy)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#monitoraccesspolicyspecaccess">access</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#monitoraccesspolicyspecidentity">identity</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#monitoraccesspolicyspecscope">scope</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#monitoraccesspolicyspeclifecycle">lifecycle</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#monitoraccesspolicyspecoperations">operations</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.access
<sup><sup>[↩ Parent](#monitoraccesspolicyspec)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>effect</b></td>
        <td>enum</td>
        <td>
          Allow or Deny access<br/>
          <br/>
            <i>Enum</i>: Allow, Deny<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>enabled</b></td>
        <td>boolean</td>
        <td>
          Whether this policy is active<br/>
          <br/>
            <i>Default</i>: true<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.identity
<sup><sup>[↩ Parent](#monitoraccesspolicyspec)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#monitoraccesspolicyspecidentitysubjects">subjects</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>priority</b></td>
        <td>integer</td>
        <td>
          Higher priority policies are evaluated first<br/>
          <br/>
            <i>Default</i>: 100<br/>
            <i>Minimum</i>: 1<br/>
            <i>Maximum</i>: 10000<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.identity.subjects
<sup><sup>[↩ Parent](#monitoraccesspolicyspecidentity)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>groups</b></td>
        <td>[]string</td>
        <td>
          List of group names<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#monitoraccesspolicyspecidentitysubjectsserviceaccountsindex">serviceAccounts</a></b></td>
        <td>[]object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>users</b></td>
        <td>[]string</td>
        <td>
          List of usernames or email addresses<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.identity.subjects.serviceAccounts[index]
<sup><sup>[↩ Parent](#monitoraccesspolicyspecidentitysubjects)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Service account name<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>namespace</b></td>
        <td>string</td>
        <td>
          Service account namespace<br/>
          <br/>
            <i>Default</i>: default<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.scope
<sup><sup>[↩ Parent](#monitoraccesspolicyspec)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#monitoraccesspolicyspecscopeclusters">clusters</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.scope.clusters
<sup><sup>[↩ Parent](#monitoraccesspolicyspecscope)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>default</b></td>
        <td>enum</td>
        <td>
          Default access for clusters not matching any rule<br/>
          <br/>
            <i>Enum</i>: allow, deny, none<br/>
            <i>Default</i>: none<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#monitoraccesspolicyspecscopeclustersrulesindex">rules</a></b></td>
        <td>[]object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.scope.clusters.rules[index]
<sup><sup>[↩ Parent](#monitoraccesspolicyspecscopeclusters)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#monitoraccesspolicyspecscopeclustersrulesindexselector">selector</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#monitoraccesspolicyspecscopeclustersrulesindexpermissions">permissions</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#monitoraccesspolicyspecscopeclustersrulesindexresources">resources</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.scope.clusters.rules[index].selector
<sup><sup>[↩ Parent](#monitoraccesspolicyspecscopeclustersrulesindex)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>matchLabels</b></td>
        <td>map[string]string</td>
        <td>
          Label selector for clusters<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchNames</b></td>
        <td>[]string</td>
        <td>
          Exact cluster names or patterns with wildcards<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchPattern</b></td>
        <td>string</td>
        <td>
          Regex pattern for cluster names<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.scope.clusters.rules[index].permissions
<sup><sup>[↩ Parent](#monitoraccesspolicyspecscopeclustersrulesindex)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>view</b></td>
        <td>boolean</td>
        <td>
          Can view basic cluster information<br/>
          <br/>
            <i>Default</i>: true<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>viewAuditInfo</b></td>
        <td>boolean</td>
        <td>
          Can view audit and policy information<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>viewCosts</b></td>
        <td>boolean</td>
        <td>
          Can view cost metrics<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>viewMetadata</b></td>
        <td>boolean</td>
        <td>
          Can view metadata about filtered resources (total counts, what's hidden)<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>viewMetrics</b></td>
        <td>boolean</td>
        <td>
          Can view cluster-wide metrics (CPU, memory, pod counts)<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>viewSecrets</b></td>
        <td>boolean</td>
        <td>
          Can view secret references<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>viewSensitive</b></td>
        <td>boolean</td>
        <td>
          Can view sensitive information<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.scope.clusters.rules[index].resources
<sup><sup>[↩ Parent](#monitoraccesspolicyspecscopeclustersrulesindex)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#monitoraccesspolicyspecscopeclustersrulesindexresourcesnamespaces">namespaces</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#monitoraccesspolicyspecscopeclustersrulesindexresourcesnodes">nodes</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#monitoraccesspolicyspecscopeclustersrulesindexresourcesoperators">operators</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#monitoraccesspolicyspecscopeclustersrulesindexresourcespods">pods</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.scope.clusters.rules[index].resources.namespaces
<sup><sup>[↩ Parent](#monitoraccesspolicyspecscopeclustersrulesindexresources)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#monitoraccesspolicyspecscopeclustersrulesindexresourcesnamespacesfilters">filters</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>visibility</b></td>
        <td>enum</td>
        <td>
          Namespace visibility level<br/>
          <br/>
            <i>Enum</i>: all, none, filtered<br/>
            <i>Default</i>: all<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.scope.clusters.rules[index].resources.namespaces.filters
<sup><sup>[↩ Parent](#monitoraccesspolicyspecscopeclustersrulesindexresourcesnamespaces)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>allowed</b></td>
        <td>[]string</td>
        <td>
          Allowed namespace names or patterns<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>denied</b></td>
        <td>[]string</td>
        <td>
          Denied namespace names or patterns<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.scope.clusters.rules[index].resources.nodes
<sup><sup>[↩ Parent](#monitoraccesspolicyspecscopeclustersrulesindexresources)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#monitoraccesspolicyspecscopeclustersrulesindexresourcesnodesfilters">filters</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>visibility</b></td>
        <td>enum</td>
        <td>
          Node visibility level<br/>
          <br/>
            <i>Enum</i>: all, none, filtered<br/>
            <i>Default</i>: all<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.scope.clusters.rules[index].resources.nodes.filters
<sup><sup>[↩ Parent](#monitoraccesspolicyspecscopeclustersrulesindexresourcesnodes)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>hideByLabels</b></td>
        <td>map[string]string</td>
        <td>
          Hide nodes with specific labels<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>hideMasters</b></td>
        <td>boolean</td>
        <td>
          Hide master/control plane nodes<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>labelSelector</b></td>
        <td>map[string]string</td>
        <td>
          Label selector for nodes<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.scope.clusters.rules[index].resources.operators
<sup><sup>[↩ Parent](#monitoraccesspolicyspecscopeclustersrulesindexresources)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#monitoraccesspolicyspecscopeclustersrulesindexresourcesoperatorsfilters">filters</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>visibility</b></td>
        <td>enum</td>
        <td>
          Operator visibility level<br/>
          <br/>
            <i>Enum</i>: all, none, filtered<br/>
            <i>Default</i>: all<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.scope.clusters.rules[index].resources.operators.filters
<sup><sup>[↩ Parent](#monitoraccesspolicyspecscopeclustersrulesindexresourcesoperators)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>allowedNames</b></td>
        <td>[]string</td>
        <td>
          Specific operator names to show<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>allowedNamespaces</b></td>
        <td>[]string</td>
        <td>
          Namespaces where operators are visible<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>deniedNames</b></td>
        <td>[]string</td>
        <td>
          Specific operator names to hide<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>deniedNamespaces</b></td>
        <td>[]string</td>
        <td>
          Namespaces where operators are hidden<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.scope.clusters.rules[index].resources.pods
<sup><sup>[↩ Parent](#monitoraccesspolicyspecscopeclustersrulesindexresources)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#monitoraccesspolicyspecscopeclustersrulesindexresourcespodsfilters">filters</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>visibility</b></td>
        <td>enum</td>
        <td>
          Pod visibility level<br/>
          <br/>
            <i>Enum</i>: all, none, filtered<br/>
            <i>Default</i>: all<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.scope.clusters.rules[index].resources.pods.filters
<sup><sup>[↩ Parent](#monitoraccesspolicyspecscopeclustersrulesindexresourcespods)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>allowedNamespaces</b></td>
        <td>[]string</td>
        <td>
          Namespaces where pods are visible<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.lifecycle
<sup><sup>[↩ Parent](#monitoraccesspolicyspec)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#monitoraccesspolicyspeclifecyclevalidity">validity</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.lifecycle.validity
<sup><sup>[↩ Parent](#monitoraccesspolicyspeclifecycle)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>notAfter</b></td>
        <td>string</td>
        <td>
          Policy expires after this time<br/>
          <br/>
            <i>Format</i>: date-time<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>notBefore</b></td>
        <td>string</td>
        <td>
          Policy is not valid before this time<br/>
          <br/>
            <i>Format</i>: date-time<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.operations
<sup><sup>[↩ Parent](#monitoraccesspolicyspec)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#monitoraccesspolicyspecoperationsaudit">audit</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.spec.operations.audit
<sup><sup>[↩ Parent](#monitoraccesspolicyspecoperations)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>logAccess</b></td>
        <td>boolean</td>
        <td>
          Log all access attempts using this policy<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>requireReason</b></td>
        <td>boolean</td>
        <td>
          Require reason for access<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.status
<sup><sup>[↩ Parent](#monitoraccesspolicy)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>affectedGroups</b></td>
        <td>integer</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>affectedServiceAccounts</b></td>
        <td>integer</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>affectedUsers</b></td>
        <td>integer</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>compiledAt</b></td>
        <td>string</td>
        <td>
          <br/>
          <br/>
            <i>Format</i>: date-time<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#monitoraccesspolicystatusconditionsindex">conditions</a></b></td>
        <td>[]object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>evaluationCount</b></td>
        <td>integer</td>
        <td>
          <br/>
          <br/>
            <i>Default</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>hash</b></td>
        <td>string</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>lastEvaluated</b></td>
        <td>string</td>
        <td>
          <br/>
          <br/>
            <i>Format</i>: date-time<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>state</b></td>
        <td>enum</td>
        <td>
          <br/>
          <br/>
            <i>Enum</i>: Active, Inactive, Error, Pending, Expired<br/>
            <i>Default</i>: Pending<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MonitorAccessPolicy.status.conditions[index]
<sup><sup>[↩ Parent](#monitoraccesspolicystatus)</sup></sup>





<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>lastTransitionTime</b></td>
        <td>string</td>
        <td>
          <br/>
          <br/>
            <i>Format</i>: date-time<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>reason</b></td>
        <td>string</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>status</b></td>
        <td>string</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>string</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>
