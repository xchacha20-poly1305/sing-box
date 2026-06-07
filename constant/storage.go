package constant

const (
	CacheFileStorageSizeLimit    = 1024 * 1024
	CacheFileStorageKeySizeLimit = 64
	CacheFileStorageEntryLimit   = CacheFileStorageSizeLimit / CacheFileStorageKeySizeLimit
)
