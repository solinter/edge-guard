use crate::error::AppError;
use maxminddb::{geoip2, MaxMindDBError, Reader};
use std::{fs, net::IpAddr};

#[derive(Debug, Clone)]
pub struct GeoInfo {
    pub country_iso: Option<String>,
    pub continent_code: Option<String>,
    pub is_in_eu: Option<bool>,
}

#[derive(Debug)]
pub struct GeoIpResolver {
    reader: Option<Reader<Vec<u8>>>,
}

impl GeoIpResolver {
    #[cfg(test)]
    pub fn disabled() -> Self {
        Self { reader: None }
    }

    pub fn from_mmdb_file(path: &str) -> Result<Self, AppError> {
        let bytes = fs::read(path)
            .map_err(|e| AppError::Config(format!("failed to read GEOIP DB file '{path}': {e}")))?;
        let reader = Reader::from_source(bytes)
            .map_err(|e| AppError::Config(format!("failed to parse GEOIP DB file '{path}': {e}")))?;
        Ok(Self {
            reader: Some(reader),
        })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        let Some(reader) = &self.reader else {
            return None;
        };

        match reader.lookup::<geoip2::Country<'_>>(ip) {
            Ok(country_record) => {
                let country_iso = country_record
                    .country
                    .as_ref()
                    .and_then(|c| c.iso_code)
                    .map(ToString::to_string);
                let continent_code = country_record
                    .continent
                    .as_ref()
                    .and_then(|c| c.code)
                    .map(ToString::to_string);
                let is_in_eu = country_record
                    .country
                    .as_ref()
                    .and_then(|c| c.is_in_european_union);
                Some(GeoInfo {
                    country_iso,
                    continent_code,
                    is_in_eu,
                })
            }
            Err(MaxMindDBError::AddressNotFoundError(_)) => None,
            Err(_) => None,
        }
    }
}
