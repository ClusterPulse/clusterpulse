# API Reference

Packages:

- [clusterpulse.io/v1alpha1](#clusterpulseiov1alpha1)

# clusterpulse.io/v1alpha1

Resource Types:

- [ClusterConnection](#clusterconnection)




## ClusterConnection
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
      <td>ClusterConnection</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b><a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#objectmeta-v1-meta">metadata</a></b></td>
      <td>object</td>
      <td>Refer to the Kubernetes API documentation for the fields of the `metadata` field.</td>
      <td>true</td>
      </tr><tr>
        <td><b><a href="#clusterconnectionspec">spec</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#clusterconnectionstatus">status</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterConnection.spec
<sup><sup>[↩ Parent](#clusterconnection)</sup></sup>





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
        <td><b><a href="#clusterconnectionspeccredentialsref">credentialsRef</a></b></td>
        <td>object</td>
        <td>
          Reference to secret containing credentials<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>endpoint</b></td>
        <td>string</td>
        <td>
          Cluster API endpoint URL<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>displayName</b></td>
        <td>string</td>
        <td>
          Human-friendly name for the cluster<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>labels</b></td>
        <td>map[string]string</td>
        <td>
          Labels for cluster categorization<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#clusterconnectionspecmonitoring">monitoring</a></b></td>
        <td>object</td>
        <td>
          Monitoring configuration<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterConnection.spec.credentialsRef
<sup><sup>[↩ Parent](#clusterconnectionspec)</sup></sup>



Reference to secret containing credentials

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
          Name of the secret<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>namespace</b></td>
        <td>string</td>
        <td>
          Namespace of the secret (defaults to same namespace)<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterConnection.spec.monitoring
<sup><sup>[↩ Parent](#clusterconnectionspec)</sup></sup>



Monitoring configuration

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
        <td><b>interval</b></td>
        <td>integer</td>
        <td>
          Reconciliation interval in seconds<br/>
          <br/>
            <i>Default</i>: 30<br/>
            <i>Minimum</i>: 30<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>timeout</b></td>
        <td>integer</td>
        <td>
          Connection timeout in seconds<br/>
          <br/>
            <i>Default</i>: 10<br/>
            <i>Minimum</i>: 5<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterConnection.status
<sup><sup>[↩ Parent](#clusterconnection)</sup></sup>





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
        <td><b>health</b></td>
        <td>enum</td>
        <td>
          <br/>
          <br/>
            <i>Enum</i>: healthy, degraded, unhealthy, unknown<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>lastSyncTime</b></td>
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
        <td><b>namespaces</b></td>
        <td>integer</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>nodes</b></td>
        <td>integer</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>phase</b></td>
        <td>enum</td>
        <td>
          <br/>
          <br/>
            <i>Enum</i>: Connected, Disconnected, Error, Unknown<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>
