use crate::{api, operation_key, validation};

pub const HELP: &str = "Usage: asterctl (--token TOKEN | --token-file PATH) [OPTIONS] subscribe
                --journal PATH --client-id ID
                --scope SCOPE --operation-key KEY|auto [SUBSCRIBE-OPTIONS] TOPIC

Create a persistent Event subscription and print its ID.

SUBSCRIBE OPTIONS:
      --journal PATH            Required existing durable client journal
      --client-id ID            Required stable owning client identity
      --scope SCOPE             Required Event scope; append '/*' to include all sub-scopes
      --operation-key KEY|auto  Required UTF-8 key, 1–256 bytes; auto generates a key
      --help                    Show this help

See asterctl --help for global options.
Generated keys are printed to stderr before sending and included in JSON output.
An identical existing subscription returns its ID with exit code 0.
";

#[derive(Debug, Default, PartialEq)]
pub struct Subscription {
    pub identity: crate::journal::Identity,
    pub request: api::CreateEventSubscriptionRequest,
    operation_key: Option<operation_key::Selection>,
}

impl Subscription {
    pub fn set_topic(&mut self, topic: &str) -> Result<(), &'static str> {
        if !self.request.topic.is_empty() {
            return Err("subscribe accepts only one TOPIC argument");
        }
        validation::topic(topic)?;
        self.request.topic = topic.to_owned();
        Ok(())
    }

    pub fn set_option(&mut self, name: &str, value: String) -> Result<(), &'static str> {
        match name {
            "--scope" => {
                let (scope, descendants) = value
                    .strip_suffix("/*")
                    .map_or((value.as_str(), false), |s| (s, true));
                validation::scope(scope)?;
                self.request.scope = scope.to_owned();
                self.request.include_descendant_scopes = descendants;
            }
            "--operation-key" => {
                self.operation_key = Some(operation_key::Selection::parse(value)?);
            }
            _ => unreachable!("subscribe option"),
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.request.topic.is_empty() {
            return Err("TOPIC is required; see subscribe --help");
        }
        if self.request.scope.is_empty() {
            return Err("--scope is required; see subscribe --help");
        }
        if self.operation_key.is_none() {
            return Err(operation_key::REQUIRED);
        }
        Ok(())
    }

    pub fn into_request(
        mut self,
    ) -> Result<(api::CreateEventSubscriptionRequest, operation_key::Key), &'static str> {
        let key = self
            .operation_key
            .ok_or(operation_key::REQUIRED)?
            .resolve()?;
        self.request.operation_key = key.value.as_bytes().to_vec();
        Ok((self.request, key))
    }
}
