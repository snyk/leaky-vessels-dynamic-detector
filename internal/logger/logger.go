/*
 * © 2024 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package logger

import (
	"log"
	"os"
	"sync/atomic"

	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
)

var l atomic.Pointer[logr.Logger]

func init() {
	logger := stdr.New(log.New(os.Stdout, "[ebpf-detector] ", log.LstdFlags|log.Lshortfile))
	if os.Getenv("DEBUG") == "true" {
		stdr.SetVerbosity(8)
	} else {
		stdr.SetVerbosity(4)
	}

	l.Store(&logger)
}

func getLogger() logr.Logger {
	return *l.Load()
}

func Info(msg string, keysAndValues ...interface{}) {
	getLogger().V(4).Info(msg, keysAndValues...)
}

func Error(err error, msg string, keysAndValues ...interface{}) {
	getLogger().Error(err, msg, keysAndValues...)
}

func Debug(msg string, keysAndValues ...interface{}) {
	getLogger().V(8).Info(msg, keysAndValues...)
}

func Warn(msg string, keysAndValues ...interface{}) {
	getLogger().V(1).Info(msg, keysAndValues...)
}
