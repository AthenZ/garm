# Configuration Detail

<!-- TOC -->

- [TLS](#tls)
- [Athenz n-token](#athenz-n-token)
- [Request filtering](#request-filtering)
- [Admin domain](#admin-domain)
- [Service domains](#service-domains)
- [Resource mapping](#resource-mapping)
- [Optional API group and resource name control](#optional-api-group-and-resource-name-control)
- [Mapping for non-resources or empty namespace](#mapping-for-non-resources-or-empty-namespace)
- [Appendix](#appendix)

<!-- /TOC -->
<!--markdownlint-disable MD036-->

## TLS

![TLS](./assets/tls.png)

**Related configuration**
1. For garm, `config.yaml`
  ```yaml
  server.tls.ca
  server.tls.cert
  server.tls.key

  athenz.root_ca
  ```
1. For kube-apiserver, `authz.yaml`
  ```yaml
  # https://github.com/kubernetes/apiserver/blob/master/plugin/pkg/authorizer/webhook/webhook.go#L69
  clusters.cluster.certificate-authority

  # https://github.com/kubernetes/apiserver/blob/master/plugin/pkg/authorizer/webhook/webhook.go#L76-L77
  users.user.client-certificate
  users.user.client-key
  ```

**Note**
- Garm uses the same server certificate for /authn and /authz.
- If `server.tls.ca` is not set, garm will not verify the client certificate of kube-apiserver.

---

## Athenz n-token

**Related configuration**
```yaml
athenz.auth_header

athenz.token.*
```
**Note**
- N-token is for identifying a service (i.e. garm) in Athenz. Athenz then use the pre-configurated policy to check whether the requested access is authenticated.
- N-token is sent to Athenz on every authentication request on the HTTP header with name `athenz.auth_header`.
- If `athenz.token.ntoken_path` is set ([Copper Argos](https://github.com/AthenZ/athenz/blob/master/docs/copper_argos_dev.md)), garm will use the n-token in the file directly.
  - It is better to set `athenz.token.validate_token: true` in this case.
  - If `athenz.token.ntoken_path` is NOT set, garm will handle the token generation and update automatically.
  - As the token is signed by `athenz.token.private_key`, please make sure that the corresponding public key is configurated in Athenz with the same `athenz.token.key_version`.

---

## Request filtering

**Related configuration**
```yaml
map_rule.tld.platform.black_list
map_rule.tld.platform.white_list

map_rule.tld.service_athenz_domains
```

**Note**
- Garm can directly reject kube-apiserver requests without querying Athenz.
- `in black_list AND NOT in white_list` => directly reject
- Support wildcard `*` matching.

---

## Admin domain

**Related configuration**
```yaml
map_rule.tld.platform.admin_access_list
map_rule.tld.platform.admin_athenz_domain
```

**Note**
- Garm can map kube-apiserver requests using a separate admin domain in Athenz.
- If the request matches any rules in `map_rule.tld.platform.admin_access_list`, garm will use `map_rule.tld.platform.admin_athenz_domain`.
- Garm will send 1 more request than the number of `map_rule.tld.service_athenz_domains` to Athenz. The kube-apiserver request is allowed if any 1 is allowed in Athenz (OR logic).
- If `service_domain_a` and `service_domain_b` are specified in `map_rule.tld.service_athenz_domains`, it is requested 3 times.
  1. Athenz resource **with** `service_domain_a` (One of those specified in `map_rule.tld.service_athenz_domains`)
  1. Athenz resource **with** `service_domain_b` (One of those specified in `map_rule.tld.service_athenz_domains`)
  1. Athenz resource **without** `map_rule.tld.service_athenz_domains`

---

## Service domains

**Related configuration**
```yaml
map_rule.tld.service_athenz_domains
```

**Note**
- If the request not matches any rules in `map_rule.tld.platform.admin_access_list`, garm will use `map_rule.tld.service_athenz_domains`.
- Garm will send request number of `map_rule.tld.service_athenz_domains` to Athenz. The kube-apiserver request is allowed if any 1 is allowed in Athenz (OR logic).
- If `service_domain_a` and `service_domain_b` are specified, garm will be requested twice.

---

## Resource mapping

**Related configuration**
```yaml
map_rule.tld.platform.resource_mappings
map_rule.tld.platform.verb_mappings
```

**Note**
- Garm can map k8s resource to Athenz resource.
- `spec.resourceAttributes.subresource` is appended to `spec.resourceAttributes.resource` before mapping as `spec.resourceAttributes.resource` with format `${resource}.${subresource}`.

---

## Optional API group and resource name control

**Related configuration**
```yaml
map_rule.tld.platform.api_group_control
map_rule.tld.platform.api_group_mappings

map_rule.tld.platform.resource_name_control
map_rule.tld.platform.resource_name_mappings
```

**Note**
- Garm will only map `spec.resourceAttributes.group` and `spec.resourceAttributes.name` in kube-apiserver request body when `map_rule.tld.platform.*_control` is `true`. Else, they will be treated as `""` during mapping.

---

## Mapping for non-resources or empty namespace

**Related configuration**
```yaml
map_rule.tld.platform.empty_namespace

map_rule.tld.platform.non_resource_api_group
map_rule.tld.platform.non_resource_namespace
```

**Note**
- Garm can substitute empty or missing value from kube-apiserver request with above configuration.
- In case of non-resource, resource is equal to `spec.non-resource-attributes.path`.

---

## Appendix
- Above resources,
  - `k8s resource`: ([refer](https://github.com/kubernetes/apiserver/blob/master/plugin/pkg/authorizer/webhook/webhook.go#L165))
  - `resource`: a variable inside garm
  - `Athenz resource`: resource inside policy
