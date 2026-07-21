use std::sync::Arc;

use async_trait::async_trait;
use commonware_runtime::Blob as _;

type StorageResult<T> = Result<T, String>;

#[derive(Clone)]
pub struct ArtifactStoreConfig {
    storage: Option<Arc<dyn ArtifactStorage>>,
}

impl ArtifactStoreConfig {
    pub fn new<S: commonware_runtime::Storage>(storage: S) -> Self {
        Self {
            storage: Some(Arc::new(CommonwareStorage(storage))),
        }
    }

    pub fn memory() -> Self {
        Self { storage: None }
    }

    pub(crate) fn storage(&self) -> Option<Arc<dyn ArtifactStorage>> {
        self.storage.clone()
    }
}

#[async_trait]
pub(crate) trait ArtifactStorage: Send + Sync {
    async fn scan(&self, partition: &'static str) -> StorageResult<Vec<Vec<u8>>>;
    async fn read(&self, partition: &'static str, name: Vec<u8>) -> StorageResult<Vec<u8>>;
    async fn write_once(
        &self,
        partition: &'static str,
        name: Vec<u8>,
        value: Vec<u8>,
    ) -> StorageResult<Option<Vec<u8>>>;
    async fn replace(
        &self,
        partition: &'static str,
        name: Vec<u8>,
        value: Vec<u8>,
    ) -> StorageResult<()>;
}

struct CommonwareStorage<S>(S);

#[async_trait]
impl<S: commonware_runtime::Storage> ArtifactStorage for CommonwareStorage<S> {
    async fn scan(&self, partition: &'static str) -> StorageResult<Vec<Vec<u8>>> {
        match self.0.scan(partition).await {
            Ok(names) => Ok(names),
            Err(commonware_runtime::Error::PartitionMissing(_)) => Ok(Vec::new()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn read(&self, partition: &'static str, name: Vec<u8>) -> StorageResult<Vec<u8>> {
        let (blob, size) = self
            .0
            .open(partition, &name)
            .await
            .map_err(|err| err.to_string())?;
        let len = usize::try_from(size).map_err(|_| format!("blob is too large: {size}"))?;
        let bytes = blob
            .read_at(0, len)
            .await
            .map_err(|err| err.to_string())?
            .coalesce();
        Ok(bytes.as_ref().to_vec())
    }

    async fn write_once(
        &self,
        partition: &'static str,
        name: Vec<u8>,
        value: Vec<u8>,
    ) -> StorageResult<Option<Vec<u8>>> {
        let (blob, size) = self
            .0
            .open(partition, &name)
            .await
            .map_err(|err| err.to_string())?;
        if size != 0 {
            let len = usize::try_from(size).map_err(|_| format!("blob is too large: {size}"))?;
            let bytes = blob
                .read_at(0, len)
                .await
                .map_err(|err| err.to_string())?
                .coalesce();
            return Ok(Some(bytes.as_ref().to_vec()));
        }
        blob.write_at_sync(0, value)
            .await
            .map_err(|err| err.to_string())?;
        Ok(None)
    }

    async fn replace(
        &self,
        partition: &'static str,
        name: Vec<u8>,
        value: Vec<u8>,
    ) -> StorageResult<()> {
        let (blob, _) = self
            .0
            .open(partition, &name)
            .await
            .map_err(|err| err.to_string())?;
        blob.resize(0).await.map_err(|err| err.to_string())?;
        blob.write_at(0, value)
            .await
            .map_err(|err| err.to_string())?;
        blob.sync().await.map_err(|err| err.to_string())
    }
}
