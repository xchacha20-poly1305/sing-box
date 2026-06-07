package cachefile

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"io"
	"slices"
	"time"

	"github.com/sagernet/bbolt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

type storageData struct {
	Data []byte
	Time time.Time
}

func decodeStorageData(reader io.Reader) (storage storageData, err error) {
	var length uint32
	err = binary.Read(reader, binary.BigEndian, &length)
	if err != nil {
		err = E.Cause(err, "read length")
		return
	}
	if length > C.CacheFileStorageSizeLimit {
		err = E.New("read length too big: ", length)
		return
	}
	storage.Data = make([]byte, length)
	_, err = io.ReadFull(reader, storage.Data)
	if err != nil {
		err = E.Cause(err, "read data")
		return
	}
	var sec int64
	err = binary.Read(reader, binary.BigEndian, &sec)
	if err != nil {
		err = E.Cause(err, "read sec")
		return
	}
	var nsec int64
	err = binary.Read(reader, binary.BigEndian, &nsec)
	if err != nil {
		err = E.Cause(err, "read nsec")
		return
	}
	storage.Time = time.Unix(sec, nsec)
	return
}

func encodeStorageData(storage storageData) []byte {
	builder := bytes.NewBuffer(make([]byte, 0, 4+len(storage.Data)+8+8))
	common.Must(binary.Write(builder, binary.BigEndian, uint32(len(storage.Data))))
	common.Must1(builder.Write(storage.Data))
	sec := storage.Time.Unix()
	common.Must(binary.Write(builder, binary.BigEndian, sec))
	nsec := int64(storage.Time.Nanosecond())
	common.Must(binary.Write(builder, binary.BigEndian, nsec))
	return builder.Bytes()
}

func (c *CacheFile) LoadStorage(key string) []byte {
	var data []byte
	decodeFailed := false
	err := c.view(func(t *bbolt.Tx) error {
		if bucket := c.bucket(t, bucketStorage); bucket != nil {
			if value := bucket.Get([]byte(key)); len(value) > 0 {
				storage, err := decodeStorageData(bytes.NewReader(value))
				if err != nil {
					decodeFailed = true
					return err
				}
				data = storage.Data
			}
		}
		return nil
	})
	if err != nil {
		c.logger.Warn(E.Cause(err, "read cache for key ", key))
		if decodeFailed {
			_ = c.DeleteStorage(key)
		}
		return nil
	}
	return data
}

func (c *CacheFile) StoreStorage(key string, data []byte) error {
	if len(key) > C.CacheFileStorageKeySizeLimit {
		return E.New("storage key too large: ", len(key))
	}
	if len(data) > C.CacheFileStorageSizeLimit {
		return E.New("storage data too large: ", len(data))
	}
	keyBytes := []byte(key)
	payload := encodeStorageData(storageData{
		Data: data,
		Time: time.Now(),
	})
	err := c.batch(func(t *bbolt.Tx) error {
		bucket, err := c.createBucket(t, bucketStorage)
		if err != nil {
			return err
		}
		type storageEntry struct {
			Key  string
			Data storageData
		}

		entries := make(map[string]storageData)
		usedSize := 0
		entryCount := 0
		var corruptedKeys [][]byte
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			storage, err := decodeStorageData(bytes.NewReader(v))
			if err != nil {
				c.logger.Warn(E.Cause(err, "drop corrupted storage entry ", string(k)))
				corruptedKeys = append(corruptedKeys, bytes.Clone(k))
				continue
			}
			entryKey := string(k)
			entries[entryKey] = storage
			if entryKey != key {
				usedSize += len(storage.Data)
				entryCount++
			}
		}
		for _, k := range corruptedKeys {
			if err := bucket.Delete(k); err != nil {
				return err
			}
		}

		evictionQueue := make([]storageEntry, 0, len(entries))
		for entryKey, storage := range entries {
			if entryKey == key {
				continue
			}
			evictionQueue = append(evictionQueue, storageEntry{
				Key:  entryKey,
				Data: storage,
			})
		}
		slices.SortFunc(evictionQueue, func(left, right storageEntry) int {
			if left.Data.Time.Equal(right.Data.Time) {
				return cmp.Compare(left.Key, right.Key)
			}
			return left.Data.Time.Compare(right.Data.Time)
		})

		for _, entry := range evictionQueue {
			if usedSize+len(data) <= C.CacheFileStorageSizeLimit && entryCount < C.CacheFileStorageEntryLimit {
				break
			}
			if err := bucket.Delete([]byte(entry.Key)); err != nil {
				return err
			}
			c.logger.Info("evict storage entry ", entry.Key, " to make room for ", key)
			usedSize -= len(entry.Data.Data)
			entryCount--
		}
		return bucket.Put(keyBytes, payload)
	})
	if err != nil {
		return E.Cause(err, "write storage")
	}
	return nil
}

func (c *CacheFile) DeleteStorage(key string) error {
	err := c.batch(func(t *bbolt.Tx) error {
		bucket := c.bucket(t, bucketStorage)
		if bucket == nil {
			return nil
		}
		return bucket.Delete([]byte(key))
	})
	if err != nil {
		return E.Cause(err, "delete storage")
	}
	return nil
}
