# API Reference

Packages:

- [clusterpulse.io/v1alpha1](#clusterpulseiov1alpha1)

# clusterpulse.io/v1alpha1

Resource Types:

- [RegistryConnection](#registryconnection)




## RegistryConnection
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
      <td>RegistryConnection</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b><a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#objectmeta-v1-meta">metadata</a></b></td>
      <td>object</td>
      <td>Refer to the Kubernetes API documentation for the fields of the `metadata` field.</td>
      <td>true</td>
      </tr><tr>
        <td><b><a href="#registryconnectionspec">spec</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#registryconnectionstatus">status</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### RegistryConnection.spec
<sup><sup>[↩ Parent](#registryconnection)</sup></sup>





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
        <td><b>endpoint</b></td>
        <td>string</td>
        <td>
          Registry endpoint URL<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#registryconnectionspeccredentialsref">credentialsRef</a></b></td>
        <td>object</td>
        <td>
          Reference to secret containing credentials<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>displayName</b></td>
        <td>string</td>
        <td>
          Human-friendly name for the registry<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>healthCheckPaths</b></td>
        <td>[]string</td>
        <td>
          Additional paths to check for health<br/>
          <br/>
            <i>Default</i>: [/v2/]<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>insecure</b></td>
        <td>boolean</td>
        <td>
          Allow insecure HTTP connections<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>labels</b></td>
        <td>map[string]string</td>
        <td>
          Labels for registry categorization<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#registryconnectionspecmonitoring">monitoring</a></b></td>
        <td>object</td>
        <td>
          <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>skipTLSVerify</b></td>
        <td>boolean</td>
        <td>
          Skip TLS certificate verification<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>string</td>
        <td>
          Optional type identifier for the registry (informational only)<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### RegistryConnection.spec.credentialsRef
<sup><sup>[↩ Parent](#registryconnectionspec)</sup></sup>



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
          Namespace of the secret<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### RegistryConnection.spec.monitoring
<sup><sup>[↩ Parent](#registryconnectionspec)</sup></sup>





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
        <td><b>checkCatalog</b></td>
        <td>boolean</td>
        <td>
          Enable catalog endpoint checking<br/>
          <br/>
            <i>Default</i>: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>interval</b></td>
        <td>integer</td>
        <td>
          Check interval in seconds<br/>
          <br/>
            <i>Default</i>: 60<br/>
            <i>Minimum</i>: 30<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxCatalogEntries</b></td>
        <td>integer</td>
        <td>
          Maximum catalog entries to fetch<br/>
          <br/>
            <i>Default</i>: 100<br/>
            <i>Minimum</i>: 1<br/>
            <i>Maximum</i>: 1000<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>timeout</b></td>
        <td>integer</td>
        <td>
          Request timeout in seconds<br/>
          <br/>
            <i>Default</i>: 10<br/>
            <i>Minimum</i>: 5<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### RegistryConnection.status
<sup><sup>[↩ Parent](#registryconnection)</sup></sup>





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
        <td><b>available</b></td>
        <td>boolean</td>
        <td>
          Whether registry is reachable<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>features</b></td>
        <td>map[string]boolean</td>
        <td>
          Detected registry features<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>health</b></td>
        <td>string</td>
        <td>
          Health status (healthy, degraded, unhealthy, unknown)<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>lastCheckTime</b></td>
        <td>string</td>
        <td>
          Last health check timestamp<br/>
          <br/>
            <i>Format</i>: date-time<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          Status message<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>phase</b></td>
        <td>string</td>
        <td>
          Current phase (Connecting, Connected, Error, Unknown)<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>repositoryCount</b></td>
        <td>integer</td>
        <td>
          Number of repositories (if catalog enabled)<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>responseTime</b></td>
        <td>integer</td>
        <td>
          Response time in milliseconds<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>version</b></td>
        <td>string</td>
        <td>
          Registry version<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>
