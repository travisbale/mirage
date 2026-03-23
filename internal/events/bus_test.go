package events_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/events"
	"github.com/travisbale/mirage/sdk"
)

func TestPublishReachesAllSubscribers(t *testing.T) {
	bus := events.NewBus(8)

	const n = 5
	chs := make([]<-chan aitm.Event, n)
	for i := range n {
		chs[i] = bus.Subscribe(sdk.EventSessionCreated)
	}

	bus.Publish(aitm.Event{Type: sdk.EventSessionCreated, Payload: "test-session-id"})

	for i, ch := range chs {
		select {
		case e := <-ch:
			if e.Type != sdk.EventSessionCreated {
				t.Errorf("subscriber %d: got type %q, want %q", i, e.Type, sdk.EventSessionCreated)
			}
			if e.OccurredAt.IsZero() {
				t.Errorf("subscriber %d: OccurredAt not set", i)
			}
		case <-time.After(100 * time.Millisecond):
			t.Errorf("subscriber %d: timed out waiting for event", i)
		}
	}
}

func TestPublishDoesNotReachOtherTypes(t *testing.T) {
	bus := events.NewBus(8)

	wrongCh := bus.Subscribe(sdk.EventBotDetected)
	rightCh := bus.Subscribe(sdk.EventSessionCreated)

	bus.Publish(aitm.Event{Type: sdk.EventSessionCreated})

	select {
	case <-rightCh:
	case <-time.After(100 * time.Millisecond):
		t.Error("right subscriber timed out")
	}

	select {
	case e := <-wrongCh:
		t.Errorf("wrong subscriber received event of type %q", e.Type)
	case <-time.After(20 * time.Millisecond):
		// Pass.
	}
}

func TestSlowSubscriberDoesNotBlockFastPublisher(t *testing.T) {
	const bufSize = 4
	bus := events.NewBus(bufSize)

	_ = bus.Subscribe(sdk.EventSessionCreated) // never reads

	for range bufSize {
		bus.Publish(aitm.Event{Type: sdk.EventSessionCreated})
	}

	done := make(chan struct{})
	go func() {
		bus.Publish(aitm.Event{Type: sdk.EventSessionCreated})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Millisecond):
		t.Error("Publish blocked when subscriber channel was full")
	}
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	bus := events.NewBus(8)
	ch := bus.Subscribe(sdk.EventTokensCaptured)

	bus.Publish(aitm.Event{Type: sdk.EventTokensCaptured, Payload: "a"})
	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("first event did not arrive")
	}

	bus.Unsubscribe(sdk.EventTokensCaptured, ch)
	bus.Publish(aitm.Event{Type: sdk.EventTokensCaptured, Payload: "b"})

	time.Sleep(5 * time.Millisecond)

	select {
	case _, ok := <-ch:
		if ok {
			t.Error("received event after Unsubscribe; channel should be closed")
		}
	default:
	}
}

func TestUnsubscribeIsIdempotent(t *testing.T) {
	bus := events.NewBus(8)
	ch := bus.Subscribe(sdk.EventBotDetected)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Unsubscribe panicked on second call: %v", r)
		}
	}()

	bus.Unsubscribe(sdk.EventBotDetected, ch)
	bus.Unsubscribe(sdk.EventBotDetected, ch)
}

func TestUnsubscribeNeverSubscribedChannel(t *testing.T) {
	bus := events.NewBus(8)
	foreign := make(chan aitm.Event, 8)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Unsubscribe panicked for unregistered channel: %v", r)
		}
	}()

	bus.Unsubscribe(sdk.EventPhishletReloaded, foreign)
}

func TestSubscribeFuncDeliversEvents(t *testing.T) {
	bus := events.NewBus(8)

	var count atomic.Int32
	var wg sync.WaitGroup
	wg.Add(3)

	ch := aitm.SubscribeFunc(bus, sdk.EventCredsCaptured, func(e aitm.Event) {
		count.Add(1)
		wg.Done()
	})
	defer bus.Unsubscribe(sdk.EventCredsCaptured, ch)

	for range 3 {
		bus.Publish(aitm.Event{Type: sdk.EventCredsCaptured})
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Errorf("SubscribeFunc: expected 3 calls, got %d", count.Load())
	}
}

func TestSubscribeFuncStopsAfterUnsubscribe(t *testing.T) {
	bus := events.NewBus(8)

	ch := aitm.SubscribeFunc(bus, sdk.EventDNSRecordSynced, func(e aitm.Event) {})

	goroutineDone := make(chan struct{})
	go func() {
		for range ch {
		}
		close(goroutineDone)
	}()

	bus.Unsubscribe(sdk.EventDNSRecordSynced, ch)

	select {
	case <-goroutineDone:
	case <-time.After(200 * time.Millisecond):
		t.Error("goroutine started by SubscribeFunc did not exit after Unsubscribe")
	}
}

func TestConcurrentPublishAndSubscribe(t *testing.T) {
	bus := events.NewBus(64)

	var wg sync.WaitGroup
	const publishers = 10
	const eventsPerPublisher = 100

	for range 5 {
		ch := bus.Subscribe(sdk.EventSessionCreated)
		wg.Add(1)
		go func() {
			defer wg.Done()
			timeout := time.After(2 * time.Second)
			for {
				select {
				case _, ok := <-ch:
					if !ok {
						return
					}
				case <-timeout:
					return
				}
			}
		}()
	}

	for range publishers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range eventsPerPublisher {
				bus.Publish(aitm.Event{Type: sdk.EventSessionCreated})
			}
		}()
	}

	wg.Wait()
}

func TestOccurredAtIsSetByPublish(t *testing.T) {
	bus := events.NewBus(8)
	ch := bus.Subscribe(sdk.EventSessionCompleted)
	defer bus.Unsubscribe(sdk.EventSessionCompleted, ch)

	before := time.Now()
	bus.Publish(aitm.Event{
		Type:       sdk.EventSessionCompleted,
		OccurredAt: time.Time{}, // zero — bus should set this
	})

	select {
	case e := <-ch:
		if e.OccurredAt.Before(before) {
			t.Errorf("OccurredAt %v is before publish time %v", e.OccurredAt, before)
		}
		if e.OccurredAt.IsZero() {
			t.Error("OccurredAt was not set by Publish")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for event")
	}
}

func TestBufferSizeRespected(t *testing.T) {
	const bufSize = 3
	bus := events.NewBus(bufSize)
	ch := bus.Subscribe(sdk.EventBotDetected)

	for range bufSize {
		bus.Publish(aitm.Event{Type: sdk.EventBotDetected})
	}
	// One more publish should drop (channel full).
	bus.Publish(aitm.Event{Type: sdk.EventBotDetected})

	time.Sleep(5 * time.Millisecond)

	count := 0
drain:
	for {
		select {
		case <-ch:
			count++
		default:
			break drain
		}
	}

	if count != bufSize {
		t.Errorf("expected %d buffered events, got %d", bufSize, count)
	}

	bus.Unsubscribe(sdk.EventBotDetected, ch)
}
