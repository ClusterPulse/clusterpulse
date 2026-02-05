# API Reference

Packages:

- [clusterpulse.io/v1alpha1](#clusterpulseiov1alpha1)

# clusterpulse.io/v1alpha1

Resource Types:

- [MetricSource](#metricsource)




## MetricSource
<sup><sup>[↩ Parent](#clusterpulseiov1alpha1 )</sup></sup>






MetricSource defines a custom resource collection configuration

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
      <td>MetricSource</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b><a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#objectmeta-v1-meta">metadata</a></b></td>
      <td>object</td>
      <td>Refer to the Kubernetes API documentation for the fields of the `metadata` field.</td>
      <td>true</td>
      </tr><tr>
        <td><b><a href="#metricsourcespec">spec</a></b></td>
        <td>object</td>
        <td>
          MetricSourceSpec defines the desired state of MetricSource<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#metricsourcestatus">status</a></b></td>
        <td>object</td>
        <td>
          MetricSourceStatus defines the observed state of MetricSource<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MetricSource.spec
<sup><sup>[↩ Parent](#metricsource)</sup></sup>



MetricSourceSpec defines the desired state of MetricSource

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
        <td><b><a href="#metricsourcespecfieldsindex">fields</a></b></td>
        <td>[]object</td>
        <td>
          Fields defines what to extract from each resource instance<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#metricsourcespecsource">source</a></b></td>
        <td>object</td>
        <td>
          Source defines which Kubernetes resource to collect from<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#metricsourcespecaggregationsindex">aggregations</a></b></td>
        <td>[]object</td>
        <td>
          Aggregations defines cluster-wide computations across all collected resources<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#metricsourcespeccollection">collection</a></b></td>
        <td>object</td>
        <td>
          Collection defines how and when to collect resources<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#metricsourcespeccomputedindex">computed</a></b></td>
        <td>[]object</td>
        <td>
          Computed defines derived values calculated from extracted fields<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#metricsourcespecrbac">rbac</a></b></td>
        <td>object</td>
        <td>
          RBAC defines how this resource integrates with access policies<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MetricSource.spec.fields[index]
<sup><sup>[↩ Parent](#metricsourcespec)</sup></sup>



FieldExtraction defines how to extract a single field from a resource

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
          Name is the identifier for this extracted field<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>path</b></td>
        <td>string</td>
        <td>
          Path is the JSONPath expression to extract the value<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>default</b></td>
        <td>string</td>
        <td>
          Default value when the path doesn't exist<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type specifies how to interpret the extracted value<br/>
          <br/>
            <i>Enum</i>: string, integer, float, boolean, quantity, timestamp, arrayLength<br/>
            <i>Default</i>: string<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MetricSource.spec.source
<sup><sup>[↩ Parent](#metricsourcespec)</sup></sup>



Source defines which Kubernetes resource to collect from

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
        <td>
          APIVersion of the target resource (e.g., "v1", "apps/v1")<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>kind</b></td>
        <td>string</td>
        <td>
          Kind of the target resource (e.g., "PersistentVolumeClaim", "Deployment")<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#metricsourcespecsourcelabelselector">labelSelector</a></b></td>
        <td>object</td>
        <td>
          LabelSelector filters resources by labels<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#metricsourcespecsourcenamespaces">namespaces</a></b></td>
        <td>object</td>
        <td>
          Namespaces defines which namespaces to collect from (only for Namespaced scope)<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>scope</b></td>
        <td>enum</td>
        <td>
          Scope determines collection behavior: Namespaced or Cluster<br/>
          <br/>
            <i>Enum</i>: Namespaced, Cluster<br/>
            <i>Default</i>: Namespaced<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MetricSource.spec.source.labelSelector
<sup><sup>[↩ Parent](#metricsourcespecsource)</sup></sup>



LabelSelector filters resources by labels

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
        <td><b><a href="#metricsourcespecsourcelabelselectormatchexpressionsindex">matchExpressions</a></b></td>
        <td>[]object</td>
        <td>
          matchExpressions is a list of label selector requirements. The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchLabels</b></td>
        <td>map[string]string</td>
        <td>
          matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
map is equivalent to an element of matchExpressions, whose key field is "key", the
operator is "In", and the values array contains only "value". The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MetricSource.spec.source.labelSelector.matchExpressions[index]
<sup><sup>[↩ Parent](#metricsourcespecsourcelabelselector)</sup></sup>



A label selector requirement is a selector that contains values, a key, and an operator that
relates the key and values.

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
        <td><b>key</b></td>
        <td>string</td>
        <td>
          key is the label key that the selector applies to.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>string</td>
        <td>
          operator represents a key's relationship to a set of values.
Valid operators are In, NotIn, Exists and DoesNotExist.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          values is an array of string values. If the operator is In or NotIn,
the values array must be non-empty. If the operator is Exists or DoesNotExist,
the values array must be empty. This array is replaced during a strategic
merge patch.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MetricSource.spec.source.namespaces
<sup><sup>[↩ Parent](#metricsourcespecsource)</sup></sup>



Namespaces defines which namespaces to collect from (only for Namespaced scope)

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
        <td><b>exclude</b></td>
        <td>[]string</td>
        <td>
          Exclude specifies namespace patterns to exclude (takes precedence over include)<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>include</b></td>
        <td>[]string</td>
        <td>
          Include specifies namespace patterns to include (supports wildcards)<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MetricSource.spec.aggregations[index]
<sup><sup>[↩ Parent](#metricsourcespec)</sup></sup>



Aggregation defines a cluster-wide computation across all collected resources

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
        <td><b>function</b></td>
        <td>enum</td>
        <td>
          Function specifies the aggregation operation<br/>
          <br/>
            <i>Enum</i>: count, sum, avg, min, max, percentile, distinct<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Name is the identifier for this aggregation<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>field</b></td>
        <td>string</td>
        <td>
          Field to aggregate (not required for count)<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#metricsourcespecaggregationsindexfilter">filter</a></b></td>
        <td>object</td>
        <td>
          Filter applies a condition before aggregating<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>groupBy</b></td>
        <td>string</td>
        <td>
          GroupBy produces aggregations grouped by this field's values<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>percentile</b></td>
        <td>integer</td>
        <td>
          Percentile value (only used when function is percentile)<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MetricSource.spec.aggregations[index].filter
<sup><sup>[↩ Parent](#metricsourcespecaggregationsindex)</sup></sup>



Filter applies a condition before aggregating

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
        <td><b>field</b></td>
        <td>string</td>
        <td>
          Field to filter on<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>enum</td>
        <td>
          Operator for comparison<br/>
          <br/>
            <i>Enum</i>: equals, notEquals, contains, startsWith, endsWith, greaterThan, lessThan, in, matches<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>value</b></td>
        <td>string</td>
        <td>
          Value to compare against<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### MetricSource.spec.collection
<sup><sup>[↩ Parent](#metricsourcespec)</sup></sup>



Collection defines how and when to collect resources

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
        <td><b>batchSize</b></td>
        <td>integer</td>
        <td>
          BatchSize for API pagination<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Default</i>: 500<br/>
            <i>Minimum</i>: 10<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>intervalSeconds</b></td>
        <td>integer</td>
        <td>
          IntervalSeconds between collection cycles (minimum 30)<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Default</i>: 60<br/>
            <i>Minimum</i>: 30<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>maxResources</b></td>
        <td>integer</td>
        <td>
          MaxResources limits the number of resources collected per cluster<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Default</i>: 5000<br/>
            <i>Minimum</i>: 1<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>parallelism</b></td>
        <td>integer</td>
        <td>
          Parallelism for concurrent field extractions<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Default</i>: 3<br/>
            <i>Minimum</i>: 1<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>retryAttempts</b></td>
        <td>integer</td>
        <td>
          RetryAttempts on transient failures<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Default</i>: 3<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>timeoutSeconds</b></td>
        <td>integer</td>
        <td>
          TimeoutSeconds for per-cluster collection<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Default</i>: 30<br/>
            <i>Minimum</i>: 5<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MetricSource.spec.computed[index]
<sup><sup>[↩ Parent](#metricsourcespec)</sup></sup>



ComputedField defines a derived value calculated from extracted fields

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
        <td><b>expression</b></td>
        <td>string</td>
        <td>
          Expression defines the computation using the expression language<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Name is the identifier for this computed field<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>enum</td>
        <td>
          Type specifies the result type<br/>
          <br/>
            <i>Enum</i>: string, integer, float, boolean<br/>
            <i>Default</i>: float<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MetricSource.spec.rbac
<sup><sup>[↩ Parent](#metricsourcespec)</sup></sup>



RBAC defines how this resource integrates with access policies

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
        <td><b>resourceTypeName</b></td>
        <td>string</td>
        <td>
          ResourceTypeName is the unique identifier for policy references<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>filterAggregations</b></td>
        <td>boolean</td>
        <td>
          FilterAggregations controls whether aggregations respect RBAC filtering<br/>
          <br/>
            <i>Default</i>: true<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>filterableFields</b></td>
        <td>[]string</td>
        <td>
          FilterableFields lists fields that can be filtered in policies<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MetricSource.status
<sup><sup>[↩ Parent](#metricsource)</sup></sup>



MetricSourceStatus defines the observed state of MetricSource

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
        <td><b>clustersCollected</b></td>
        <td>integer</td>
        <td>
          ClustersCollected is the number of clusters successfully collected from<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#metricsourcestatusconditionsindex">conditions</a></b></td>
        <td>[]object</td>
        <td>
          Conditions represent the latest observations<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>errorsLastRun</b></td>
        <td>integer</td>
        <td>
          ErrorsLastRun is the count of errors in the last collection cycle<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#metricsourcestatusfieldvalidationindex">fieldValidation</a></b></td>
        <td>[]object</td>
        <td>
          FieldValidation reports validation status for each field<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>lastCollectionDuration</b></td>
        <td>string</td>
        <td>
          LastCollectionDuration is how long the last collection took<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>lastCollectionTime</b></td>
        <td>string</td>
        <td>
          LastCollectionTime is when collection last completed<br/>
          <br/>
            <i>Format</i>: date-time<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          Message provides additional status information<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>phase</b></td>
        <td>enum</td>
        <td>
          Phase indicates the current state<br/>
          <br/>
            <i>Enum</i>: Active, Error, Disabled<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resourcesCollected</b></td>
        <td>integer</td>
        <td>
          ResourcesCollected is the total count from last collection<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MetricSource.status.conditions[index]
<sup><sup>[↩ Parent](#metricsourcestatus)</sup></sup>



Condition contains details for one aspect of the current state of this API Resource.

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
          lastTransitionTime is the last time the condition transitioned from one status to another.
This should be when the underlying condition changed.  If that is not known, then using the time when the API field changed is acceptable.<br/>
          <br/>
            <i>Format</i>: date-time<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          message is a human readable message indicating details about the transition.
This may be an empty string.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>reason</b></td>
        <td>string</td>
        <td>
          reason contains a programmatic identifier indicating the reason for the condition's last transition.
Producers of specific condition types may define expected values and meanings for this field,
and whether the values are considered a guaranteed API.
The value should be a CamelCase string.
This field may not be empty.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>status</b></td>
        <td>enum</td>
        <td>
          status of the condition, one of True, False, Unknown.<br/>
          <br/>
            <i>Enum</i>: True, False, Unknown<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>string</td>
        <td>
          type of condition in CamelCase or in foo.example.com/CamelCase.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>observedGeneration</b></td>
        <td>integer</td>
        <td>
          observedGeneration represents the .metadata.generation that the condition was set based upon.
For instance, if .metadata.generation is currently 12, but the .status.conditions[x].observedGeneration is 9, the condition is out of date
with respect to the current state of the instance.<br/>
          <br/>
            <i>Format</i>: int64<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### MetricSource.status.fieldValidation[index]
<sup><sup>[↩ Parent](#metricsourcestatus)</sup></sup>



FieldValidationStatus reports the validation status of a single field

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
        <td><b>field</b></td>
        <td>string</td>
        <td>
          Field name<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>status</b></td>
        <td>enum</td>
        <td>
          Status of validation<br/>
          <br/>
            <i>Enum</i>: valid, invalid, warning<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          Message provides details if status is not valid<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>
