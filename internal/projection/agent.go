/*
Copyright 2025 Buzz-IT GmbH.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package projection reports the SecLang version file actually mounted on a node.
// The operator publishes a new SecMarker only after every Envoy node reports it.
package projection

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kubewaf-io/kubewaf/internal/compile"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
)

// Run watches the mounted version file and the ConfigMap, and records the
// projected bytes for this node. It returns when ctx is cancelled.
func Run(ctx context.Context, client kubernetes.Interface, namespace, nodeName, mountDir string) error {
	var mu sync.Mutex
	var desired string
	poke := make(chan struct{}, 1)
	notify := func() {
		select {
		case poke <- struct{}{}:
		default:
		}
	}
	// Resync re-reads the mount if inotify misses kubelet's symlink swap.
	factory := informers.NewSharedInformerFactoryWithOptions(client, 2*time.Second, informers.WithNamespace(namespace))
	inf := factory.Core().V1().ConfigMaps().Informer()
	if _, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { setDesired(&mu, &desired, obj); notify() },
		UpdateFunc: func(_, obj any) { setDesired(&mu, &desired, obj); notify() },
	}); err != nil {
		return err
	}
	factory.Start(ctx.Done())
	go func() { _ = watchDir(ctx, mountDir, notify) }()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-poke:
			mu.Lock()
			want := desired
			mu.Unlock()
			if want == "" {
				continue
			}
			got, err := os.ReadFile(filepath.Join(mountDir, compile.VersionKey))
			if err != nil || string(got) != want {
				continue
			}
			if err := report(ctx, client, namespace, nodeName, string(got)); err != nil && ctx.Err() == nil {
				return err
			}
		}
	}
}

func setDesired(mu *sync.Mutex, desired *string, obj any) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok || cm.Name != compile.ConfigMapName {
		return
	}
	mu.Lock()
	*desired = cm.Data[compile.VersionKey]
	mu.Unlock()
}

func watchDir(ctx context.Context, dir string, notify func()) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer func() { _ = w.Close() }()
	if err := w.Add(dir); err != nil {
		if err := w.Add(filepath.Dir(dir)); err != nil {
			return err
		}
	}
	notify()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-w.Events:
			_ = w.Add(dir)
			notify()
		case err := <-w.Errors:
			if err != nil {
				return err
			}
		}
	}
}

func report(ctx context.Context, client kubernetes.Interface, namespace, nodeName, body string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cm, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, compile.SeenConfigMapName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err = client.CoreV1().ConfigMaps(namespace).Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: compile.SeenConfigMapName, Namespace: namespace},
				Data:       map[string]string{nodeName: body},
			}, metav1.CreateOptions{})
			return err
		}
		if err != nil {
			return err
		}
		if cm.Data[nodeName] == body {
			return nil
		}
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		cm.Data[nodeName] = body
		_, err = client.CoreV1().ConfigMaps(namespace).Update(ctx, cm, metav1.UpdateOptions{})
		return err
	})
}
