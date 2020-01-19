package flamingo

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// OutputWriter defines a function for writing results
type OutputWriter func(map[string]string) error

// OutputCleaner defines a cleanup function for a writer
type OutputCleaner func()

// OutputWriterNoOp is a do-nothing output writer
var OutputWriterNoOp = func(rec map[string]string) error {
	return nil
}

// OutputCleanerNoOp is a do-nothing output cleaner
var OutputCleanerNoOp = func() {
	return
}

// RecordWriter is used to store acquired credentials
type RecordWriter struct {
	OutputWriters  []OutputWriter
	OutputCleaners []OutputCleaner
	outputChan     chan map[string]string
	outputChanOpen bool
	m              sync.Mutex
}

// NewRecordWriter initializes a new record writer
func NewRecordWriter() *RecordWriter {
	rw := &RecordWriter{
		outputChan:     make(chan map[string]string, 500),
		outputChanOpen: true,
	}

	go rw.processRecords()
	return rw
}

// Record writes a credential to the output writers
func (r *RecordWriter) Record(proto string, source string, params map[string]string) {
	rec := make(map[string]string)
	rec["_etime"] = time.Now().Format(time.RFC3339)
	rec["_host"] = source
	rec["_proto"] = proto
	for k, v := range params {
		if _, exists := rec[k]; exists {
			continue
		}
		rec[k] = v
	}

	r.m.Lock()
	defer r.m.Unlock()
	if !r.outputChanOpen {
		return
	}
	r.outputChan <- rec
}

// Done safely closes the output channel
func (r *RecordWriter) Done() {
	r.m.Lock()
	defer r.m.Unlock()
	if !r.outputChanOpen {
		return
	}
	r.outputChanOpen = false
	close(r.outputChan)
}

// processRecords handles output processing in a goroutine
func (r *RecordWriter) processRecords() {
	for rec := range r.outputChan {
		for _, w := range r.OutputWriters {
			err := w(rec)
			if err != nil {
				log.Debugf("failed to write output %v: %s", rec, err)
			}
		}
	}
}
