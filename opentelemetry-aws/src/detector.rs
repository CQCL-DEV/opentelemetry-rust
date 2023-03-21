use std::fs;

use opentelemetry::{
    sdk::{resource::ResourceDetector, Resource},
    KeyValue,
};
use opentelemetry_semantic_conventions::resource::{
    CLOUD_PLATFORM, CLOUD_PROVIDER, CONTAINER_ID, K8S_CLUSTER_NAME,
};
use reqwest::{blocking::Response, Certificate};
use serde::Deserialize;

const CONTAINER_ID_LENGTH: usize = 64;

#[derive(Deserialize)]
struct ClusterInfoData {
    #[serde(rename = "cluster.name")]
    pub cluster_name: String,
}

#[derive(Deserialize)]
struct ClusterInfo {
    pub data: ClusterInfoData,
}

struct K8sClient {
    internal: reqwest::blocking::Client,
}

impl K8sClient {
    fn get_root_cert() -> Result<Certificate, Box<dyn std::error::Error>> {
        let k8s_cert_bytes = fs::read("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")?;
        Ok(Certificate::from_pem(&k8s_cert_bytes)?)
    }

    pub fn try_new() -> Result<Self, Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::builder()
            .add_root_certificate(K8sClient::get_root_cert()?)
            .build()?;
        Ok(Self { internal: client })
    }

    fn get_token(&self) -> Result<String, Box<dyn std::error::Error>> {
        let token_bytes = fs::read("/var/run/secrets/kubernetes.io/serviceaccount/token")?;
        Ok(String::from_utf8(token_bytes)?)
    }

    fn k8s_api_request(
        &self,
        method: reqwest::Method,
        path: &str,
        token: &str,
        timeout: std::time::Duration,
    ) -> Result<Response, reqwest::Error> {
        let request = self
            .internal
            .request(method, &format!("https:://kubernetes.default.svc{}", path))
            .bearer_auth(token)
            .timeout(timeout)
            .build()?;

        self.internal.execute(request)
    }

    pub fn is_eks(&self, timeout: std::time::Duration) -> Result<(), Box<dyn std::error::Error>> {
        self.k8s_api_request(
            reqwest::Method::GET,
            "/api/v1/namespaces/kube-system/configmaps/aws-auth",
            &self.get_token()?,
            timeout,
        )?;

        Ok(())
    }

    pub fn get_cluster_info(
        &self,
        timeout: std::time::Duration,
    ) -> Result<ClusterInfo, Box<dyn std::error::Error>> {
        Ok(self
            .k8s_api_request(
                reqwest::Method::GET,
                "/api/v1/namespaces/amazon-cloudwatch/configmaps/cluster-info",
                &self.get_token()?,
                timeout,
            )?
            .json()?)
    }
}

fn get_container_id() -> Result<String, Box<dyn std::error::Error>> {
    let mut container_id = String::new(); // default to empty CONTAINER_ID
    let cgroup = String::from_utf8(fs::read("/proc/self/cgroup")?)?;
    for line in cgroup.lines() {
        let line = line.trim();
        if line.len() > CONTAINER_ID_LENGTH {
            container_id = line[line.len() - CONTAINER_ID_LENGTH..].to_string();
            break;
        }
    }
    return Ok(container_id);
}

#[derive(Clone, Debug, Default)]
pub struct AwsEksResourceDetector {
    _private: (),
}

impl AwsEksResourceDetector {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl ResourceDetector for AwsEksResourceDetector {
    fn detect(&self, timeout: std::time::Duration) -> Resource {
        let closure = |timeout| {
            let client = K8sClient::try_new()?;

            client.is_eks(timeout)?;

            let cluster_info = client.get_cluster_info(timeout)?;
            let container_id = get_container_id()?;

            Ok(Resource::new([
                KeyValue::new(CLOUD_PROVIDER, "aws"),
                KeyValue::new(CLOUD_PLATFORM, "aws_eks"),
                KeyValue::new(K8S_CLUSTER_NAME, cluster_info.data.cluster_name),
                KeyValue::new(CONTAINER_ID, container_id),
            ]))
        };
        closure(timeout).unwrap_or_else(|err: Box<dyn std::error::Error>| {
            eprintln!("{}", err);
            Resource::empty()
        })
    }
}
