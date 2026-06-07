package clashapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/service"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func storageRouter(ctx context.Context) http.Handler {
	r := chi.NewRouter()
	r.Get("/{key}", getStorage(ctx))
	r.Put("/{key}", setStorage(ctx))
	r.Delete("/{key}", deleteStorage(ctx))
	return r
}

func getStorage(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		cacheFile := service.FromContext[adapter.CacheFile](ctx)
		if cacheFile == nil {
			render.Status(r, http.StatusNotImplemented)
			render.JSON(w, r, ErrNotImplemented)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		key := getEscapeParam(r, "key")
		storage := cacheFile.LoadStorage(key)
		if len(storage) == 0 {
			_, _ = w.Write([]byte("null"))
			return
		}
		_, _ = w.Write(storage)
	}
}

func setStorage(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		cacheFile := service.FromContext[adapter.CacheFile](ctx)
		if cacheFile == nil {
			render.Status(r, http.StatusNotImplemented)
			render.JSON(w, r, ErrNotImplemented)
			return
		}
		key := getEscapeParam(r, "key")
		if len(key) == 0 {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("missing key"))
			return
		}
		if len(key) > C.CacheFileStorageKeySizeLimit {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("key exceeds 64B limit"))
			return
		}
		data, err := io.ReadAll(io.LimitReader(r.Body, C.CacheFileStorageSizeLimit+1))
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if !json.Valid(data) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if len(data) > C.CacheFileStorageSizeLimit {
			render.Status(r, http.StatusRequestEntityTooLarge)
			render.JSON(w, r, newError("payload exceeds 1MB limit"))
			return
		}
		err = cacheFile.StoreStorage(key, data)
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.NoContent(w, r)
	}
}

func deleteStorage(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		cacheFile := service.FromContext[adapter.CacheFile](ctx)
		if cacheFile == nil {
			render.Status(r, http.StatusNotImplemented)
			render.JSON(w, r, ErrNotImplemented)
			return
		}
		key := getEscapeParam(r, "key")
		err := cacheFile.DeleteStorage(key)
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.NoContent(w, r)
	}
}
